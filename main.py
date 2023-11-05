import base64
import random
import argparse


# Créer le parser
parser = argparse.ArgumentParser(description='Générer des clés RSA')

# Ajouter les arguments
parser.add_argument('-f', '--filename', type=str, default='monRSA', help='Le nom de fichier à utiliser pour les clés')

# Analyser les arguments
args = parser.parse_args()

# Utiliser l'argument filename
filename = args.filename

# Vérifie si un nombre est premier
def is_prime(num):
    if num < 2:
        return False
    for i in range(2, int(num ** 0.5) + 1):
        if num % i == 0:
            return False
    return True

# Calcule le PGCD de deux nombres
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# Calcule l'inverse modulaire
def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

# Génère une paire de RSA public et privée
def generate_keypair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("Les deux nombres p et q doivent être premiers.")
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 65537  # Exposant public couramment utilisé

    # Trouve une clé privée 'd' telle que (d * e) % phi == 1
    d = mod_inverse(e, phi)

    clé_publique = (n, e)
    clé_privée = (n, d)
    return clé_publique, clé_privée

# Chiffre un message avec la clé publique RSA
def encrypt(clé_publique, texte_en_clair):
    n, e = clé_publique
    message_chiffré = [str(pow(ord(caractère), e, n)) for caractère in texte_en_clair]
    return ' '.join(message_chiffré)

# Déchiffre un message chiffré avec la clé privée RSA
def decrypt(clé_privée, message_chiffré):
    n, d = clé_privée
    message_déchiffré = [chr(pow(caractère, d, n)) for caractère in message_chiffré]
    return ''.join(message_déchiffré)

# Génère un nombre premier aléatoire de n bits
def generate_random_prime(bits):
    while True:
        num = random.getrandbits(bits)
        if num % 2 == 0:
            num += 1  # nombre impair
        if is_prime(num):
            return num

# Fonction principale
def main():
    commande = input("Commande : ")
    if commande == "keygen":
        bits = 10  # Ajustez la taille de la clé (recommandé : 2048 bits ou plus)
        p = generate_random_prime(bits)
        print("p =", p)
        q = generate_random_prime(bits)
        print("q =", q)
        clé_publique, clé_privée = generate_keypair(p, q)

        with open(f"{filename}.pub", "w") as pub_file:
            pub_file.write(f"---begin monRSA clé publique---\n")
            pub_file.write(base64.b64encode(clé_publique[0].to_bytes(32, byteorder='big')).decode() + '\n')
            pub_file.write(base64.b64encode(clé_publique[1].to_bytes(32, byteorder='big')).decode() + '\n')
            pub_file.write("---end monRSA clé publique---\n")

        with open(f"{filename}.priv", "w") as priv_file:
            priv_file.write(f"---begin monRSA clé privée---\n")
            priv_file.write(base64.b64encode(clé_privée[0].to_bytes(32, byteorder='big')).decode() + '\n')
            priv_file.write(base64.b64encode(clé_privée[1].to_bytes(32, byteorder='big')).decode() + '\n')
            priv_file.write("---end monRSA clé privée---\n")

    elif commande == "crypt":
        with open(f"{filename}.pub", "r") as pub_file:
            lines = pub_file.readlines()
            n = int.from_bytes(base64.b64decode(lines[1].strip()), byteorder='big')
            e = int.from_bytes(base64.b64decode(lines[2].strip()), byteorder='big')

        texte_en_clair = input("Entrez le texte à chiffrer : ")
        message_chiffré = encrypt((n, e), texte_en_clair)
        print("Cryptogramme :", message_chiffré)

    elif commande == "decrypt":
        with open(f"{filename}.priv", "r") as priv_file:
            lines = priv_file.readlines()
            n = int.from_bytes(base64.b64decode(lines[1].strip()), byteorder='big')
            d = int.from_bytes(base64.b64decode(lines[2].strip()), byteorder='big')

        message_chiffré = input("Entrez le cryptogramme : ")
        message_chiffré = [int(caractère) for caractère in message_chiffré.split()]
        message_déchiffré = decrypt((n, d), message_chiffré)
        print("Texte en clair :", message_déchiffré)

    elif commande == "help":
        print("Syntaxe :")
        print("       monRSA <commande> [<clé>] [<texte>] [switchs]")
        print("Commandes :")
        print("       keygen : Génère une paire de clés")
        print("       crypt : Chiffre <texte> avec la clé publique <clé>")
        print("       decrypt : Déchiffre <texte> avec la clé privée <clé>")
        print("       help : Affiche ce manuel")
    else:
        print("Commande invalide.")

if __name__ == "__main__":
    main()
