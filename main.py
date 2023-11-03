import base64
import random


def is_prime(num):
    if num < 2:
        return False
    for i in range(2, int(num ** 0.5) + 1):
        if num % i == 0:
            return False
    return True


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1


def generate_keypair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("Both p and q must be prime.")
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537  # Commonly used public exponent

    # Find a private key 'd' such that (d * e) % phi == 1
    d = mod_inverse(e, phi)

    public_key = (n, e)
    private_key = (n, d)
    return public_key, private_key


def encrypt(public_key, plaintext):
    n, e = public_key
    encrypted_msg = [str(pow(ord(char), e, n)) for char in plaintext]
    return ' '.join(encrypted_msg)


def decrypt(private_key, encrypted_msg):
    n, d = private_key
    decrypted_msg = [chr(pow(char, d, n)) for char in encrypted_msg]
    return ''.join(decrypted_msg)


def generate_random_prime(bits):
    while True:
        num = random.getrandbits(bits)
        if num % 2 == 0:
            num += 1  # nombre impair
        if is_prime(num):
            return num


def main():
    command = input("Commande : ")
    if command == "keygen":
        bits = 12  # ajuster la taille de la clé
        p = generate_random_prime(bits)
        print("p =", p)
        q = generate_random_prime(bits)
        print("q =", q)
        public_key, private_key = generate_keypair(p, q)

        with open("monRSA.pub", "w") as pub_file:
            pub_file.write(f"---begin monRSA public key---\n")
            pub_file.write(base64.b64encode(
                public_key[0].to_bytes(32, byteorder='big')).decode() + '\n')
            pub_file.write(base64.b64encode(
                public_key[1].to_bytes(32, byteorder='big')).decode() + '\n')
            pub_file.write("---end monRSA key---\n")

        with open("monRSA.priv", "w") as priv_file:
            priv_file.write(f"---begin monRSA private key---\n")
            priv_file.write(base64.b64encode(
                private_key[0].to_bytes(32, byteorder='big')).decode() + '\n')
            priv_file.write(base64.b64encode(
                private_key[1].to_bytes(32, byteorder='big')).decode() + '\n')
            priv_file.write("---end monRSA key---\n")

    elif command == "crypt":
        with open("monRSA.pub", "r") as pub_file:
            lines = pub_file.readlines()
            n = int.from_bytes(base64.b64decode(
                lines[1].strip()), byteorder='big')
            e = int.from_bytes(base64.b64decode(
                lines[2].strip()), byteorder='big')

        plaintext = input("Entrez le texte à chiffrer : ")
        encrypted_msg = encrypt((n, e), plaintext)
        print("Cryptogramme :", encrypted_msg)

    elif command == "decrypt":
        with open("monRSA.priv", "r") as priv_file:
            lines = priv_file.readlines()
            n = int.from_bytes(base64.b64decode(
                lines[1].strip()), byteorder='big')
            d = int.from_bytes(base64.b64decode(
                lines[2].strip()), byteorder='big')

        encrypted_msg = input("Entrez le cryptogramme : ")
        encrypted_msg = [int(char) for char in encrypted_msg.split()]
        decrypted_msg = decrypt((n, d), encrypted_msg)
        print("Texte en clair :", decrypted_msg)

    elif command == "help":
        print("Syntaxe :")
        print("       monRSA <commande> [<clé>] [<texte>] [switchs]")
        print("Commande :")
        print("       keygen : Génère une paire de clé")
        print("       crypt : Chiffre <texte> pour le clé publique <clé>")
        print("       decrypt : Déchiffre <texte> pour le clé privée <clé>")
        print("       help : Affiche ce manuel")
    else:
        print("Commande invalide.")


if __name__ == "__main__":
    main()
