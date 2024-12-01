#!/usr/bin/env python3

import sys
import os
import base64
import random
import math

def is_prime(n, k=5):
    """Test de primalité de Miller-Rabin."""
    if n <= 1:
        return False
    elif n <= 3:
        return True

    # Nombre pair
    if n % 2 == 0:
        return False

    # Écrire n sous la forme 2^r * d + 1
    r, d = 0, n - 1

    while d % 2 == 0:
        d //= 2
        r += 1

    # Boucle des témoins
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for __ in range(r - 1):
            x = pow(x, 2, n)

            if x == n - 1:
                break
        else:
            return False

    return True

def generate_large_prime(num_digits):
    """Génère un nombre premier aléatoire de num_digits chiffres."""
    while True:
        # Générer un nombre aléatoire de num_digits chiffres
        n = random.randrange(10**(num_digits - 1), 10**num_digits)
        if is_prime(n):
            return n

def extended_gcd(a, b):
    """Algorithme d'Euclide étendu."""
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x

def modular_inverse(e, phi):
    """Calcule l'inverse modulaire de e modulo phi."""
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        return None  # Pas d'inverse modulaire si e et phi ne sont pas copremiers
    else:
        return x % phi

def decimal_to_hex(n):
    """Convertit un nombre décimal en chaîne hexadécimale."""
    return hex(n)[2:]

def hex_to_decimal(s):
    """Convertit une chaîne hexadécimale en nombre décimal."""
    return int(s, 16)

def keygen(num_digits=10, filename='monRSA'):
    """Génère des clés RSA et les enregistre dans des fichiers."""
    print("Génération des clés RSA...")
    # Générer deux nombres premiers distincts p et q
    p = generate_large_prime(num_digits)
    q = generate_large_prime(num_digits)
    while q == p:
        q = generate_large_prime(num_digits)

    n = p * q
    phi = (p - 1) * (q - 1)

    # Trouver e et d
    e = 65537  # Choix commun pour e
    if math.gcd(e, phi) != 1:
        # Trouver un autre e
        for e in range(3, phi, 2):
            if is_prime(e) and math.gcd(e, phi) == 1:
                break

    d = modular_inverse(e, phi)
    if d is None or e == d:
        # Trouver d
        for e in range(3, phi, 2):
            if is_prime(e) and math.gcd(e, phi) == 1:
                d = modular_inverse(e, phi)
                if d is not None and e != d and (e * d) % phi == 1:
                    break

    # Enregistrer les clés dans des fichiers
    n_hex = decimal_to_hex(n)
    d_hex = decimal_to_hex(d)
    e_hex = decimal_to_hex(e)

    # Clé privée
    priv_content = '---begin monRSA private key---\n'
    priv_content += base64.b64encode((n_hex + '\n' + d_hex).encode()).decode() + '\n'
    priv_content += '---end monRSA key---\n'

    # Clé publique
    pub_content = '---begin monRSA public key---\n'
    pub_content += base64.b64encode((n_hex + '\n' + e_hex).encode()).decode() + '\n'
    pub_content += '---end monRSA key---\n'

    with open(f'{filename}.priv', 'w') as f:
        f.write(priv_content)

    with open(f'{filename}.pub', 'w') as f:
        f.write(pub_content)

    print(f"Clés générées et enregistrées dans {filename}.priv et {filename}.pub")

def read_key_file(filename, key_type):
    """Lit et analyse le fichier de clé."""
    with open(filename, 'r') as f:
        lines = f.readlines()

    if key_type == 'public':
        if lines[0].strip() != '---begin monRSA public key---':
            print("Format de fichier de clé publique invalide.")
            sys.exit(1)
    else:
        if lines[0].strip() != '---begin monRSA private key---':
            print("Format de fichier de clé privée invalide.")
            sys.exit(1)

    b64_data = lines[1].strip()
    decoded_data = base64.b64decode(b64_data).decode()
    n_hex, key_hex = decoded_data.split('\n')

    n = hex_to_decimal(n_hex)
    key = hex_to_decimal(key_hex)

    return n, key

def crypt(key_file, plaintext):
    """Chiffre le texte en clair en utilisant la clé publique."""
    n, e = read_key_file(key_file, 'public')

    print(f"n = {n}")
    print(f"e = {e}")

    # Convertir le texte en codes ASCII
    ascii_codes = ''.join([str(ord(char)).zfill(3) for char in plaintext])
    print(f"ASCII codes: {ascii_codes}")

    # Calculer la taille du bloc
    block_size = len(str(n)) - 1
    print(f"Block size: {block_size}")

    # Ajouter des zéros en tête pour que la longueur soit divisible par block_size
    padding_length = (-len(ascii_codes)) % block_size
    ascii_codes = '0' * padding_length + ascii_codes

    # Diviser en blocs
    blocks = [ascii_codes[i:i+block_size] for i in range(0, len(ascii_codes), block_size)]
    print(f"Blocks: {blocks}")

    # Chiffrer chaque bloc
    encrypted_blocks = []
    for block in blocks:
        B = int(block)
        C = pow(B, e, n)
        encrypted_blocks.append(str(C).zfill(block_size + 1))
    print(f"Encrypted blocks: {encrypted_blocks}")

    # Assembler les blocs chiffrés sans espaces
    encrypted_data = ','.join(encrypted_blocks)
    print(f"Encrypted sequence: {encrypted_data}")

    # Encoder en Base64 pour préserver les zéros de tête
    encrypted_bytes = base64.b64encode(encrypted_data.encode('utf-8'))
    print(f"Encrypted bytes: {encrypted_bytes}")

    final_cipher = encrypted_bytes.decode()
    print(final_cipher)


def decrypt(key_file, ciphertext):
    """Déchiffre le texte chiffré en utilisant la clé privée."""
    n, d = read_key_file(key_file, 'private')

    # Décoder le Base64 pour obtenir la chaîne de chiffres chiffrés
    try:
        encrypted_data = base64.b64decode(ciphertext).decode('utf-8')
        print(f"Données chiffrées décodées : {encrypted_data}")
    except Exception as e:
        print(f"Erreur lors du décodage Base64 : {e}")
        sys.exit(1)

    # Supprimer les virgules si nécessaire
    encrypted_data = encrypted_data.replace(',', '')
    print(f"Données après suppression des virgules : {encrypted_data}")

    # Calculer la taille du bloc
    block_size = len(str(n))
    print(f"Taille des blocs attendue : {block_size}")

    # Diviser en blocs
    blocks = [encrypted_data[i:i+block_size] for i in range(0, len(encrypted_data), block_size)]
    print(f"Blocs chiffrés : {blocks}")

    # Déchiffrer chaque bloc
    decrypted_blocks = []
    for block in blocks:
        try:
            C = int(block)  # Conversion de la chaîne en entier
            B = pow(C, d, n)
            decrypted_blocks.append(str(B).zfill(block_size - 1))
        except ValueError as ve:
            print(f"Erreur lors de la conversion en entier ou du déchiffrement : {ve}")
            sys.exit(1)
    print(f"Blocs déchiffrés : {decrypted_blocks}")

    # Assembler les blocs déchiffrés
    decrypted_data = ''.join(decrypted_blocks)

    # Retirer les zéros de padding
    decrypted_data = decrypted_data.lstrip('0')

    # Diviser en codes ASCII de 3 chiffres
    ascii_codes = [decrypted_data[i:i+3] for i in range(0, len(decrypted_data), 3)]

    # Convertir en caractères
    try:
        plaintext = ''.join([chr(int(code)) for code in ascii_codes])
    except ValueError as ve:
        print(f"Erreur lors de la conversion des codes ASCII : {ve}")
        sys.exit(1)

    print(f"Texte clair déchiffré : {plaintext}")
    return plaintext

def print_help():
    help_text = """
Script monRSA par Nug
Syntaxe :
monRSA <commande> [<clé>] [<texte>] [switchs]
Commande :
keygen : Génère une paire de clé
crypt : Chiffre <texte> pour la clé publique <clé>
decrypt: Déchiffre <texte> pour la clé privée <clé>
help : Affiche ce manuel
Clé :
Un fichier qui contient une clé publique monRSA ("crypt") ou une clé privée ("decrypt")
Texte :
Une phrase en clair ("crypt") ou une phrase chiffrée ("decrypt")
Switchs :
-f <file> permet de choisir le nom des clés générées, monRSA.pub et monRSA.priv par défaut
-s <size> permet de choisir la taille des clés en chiffres (10 par défaut)
-i <file> permet de fournir un fichier d'entrée
-o <file> permet de spécifier un fichier de sortie
"""
    print(help_text)

def main():
    if len(sys.argv) < 2 or sys.argv[1] == 'help':
        print_help()
        sys.exit(0)

    command = sys.argv[1]
    if command == 'keygen':
        # Gestion des switchs
        filename = 'monRSA'
        num_digits = 10
        if '-f' in sys.argv:
            idx = sys.argv.index('-f')
            if idx + 1 < len(sys.argv):
                filename = sys.argv[idx + 1]
            else:
                print("Erreur: -f nécessite un argument.")
                sys.exit(1)
        if '-s' in sys.argv:
            idx = sys.argv.index('-s')
            if idx + 1 < len(sys.argv):
                try:
                    num_digits = int(sys.argv[idx + 1])
                except ValueError:
                    print("Erreur: -s nécessite un entier comme argument.")
                    sys.exit(1)
            else:
                print("Erreur: -s nécessite un argument.")
                sys.exit(1)

        keygen(num_digits=num_digits, filename=filename)

    elif command == 'crypt':
        if len(sys.argv) < 4:
            print("Erreur: 'crypt' nécessite un fichier de clé et un texte.")
            sys.exit(1)

        key_file = sys.argv[2]
        plaintext = sys.argv[3]

        # Gestion des switchs
        input_file = None
        output_file = None
        if '-i' in sys.argv:
            idx = sys.argv.index('-i')
            if idx + 1 < len(sys.argv):
                input_file = sys.argv[idx + 1]
            else:
                print("Erreur: -i nécessite un fichier.")
                sys.exit(1)
        if '-o' in sys.argv:
            idx = sys.argv.index('-o')
            if idx + 1 < len(sys.argv):
                output_file = sys.argv[idx + 1]
            else:
                print("Erreur: -o nécessite un fichier.")
                sys.exit(1)

        if input_file:
            if not os.path.exists(input_file):
                print(f"Erreur: Le fichier d'entrée '{input_file}' n'existe pas.")
                sys.exit(1)
            with open(input_file, 'r') as f:
                plaintext = f.read()

        # Chiffrer
        encrypted_text = ''
        try:
            from io import StringIO
            # Capture l'output de la fonction crypt
            import contextlib

            with contextlib.redirect_stdout(StringIO()) as f:
                crypt(key_file, plaintext)
                encrypted_text = f.getvalue().strip()
        except Exception as e:
            print("Erreur lors du chiffrement:", e)
            sys.exit(1)

        if output_file:
            with open(output_file, 'w') as f:
                f.write(encrypted_text)
        else:
            print(encrypted_text)

    elif command == 'decrypt':
        if len(sys.argv) < 4:
            print("Erreur: 'decrypt' nécessite un fichier de clé et un texte chiffré.")
            sys.exit(1)

        key_file = sys.argv[2]
        ciphertext = sys.argv[3]

        # Gestion des switchs
        input_file = None
        output_file = None
        if '-i' in sys.argv:
            idx = sys.argv.index('-i')
            if idx + 1 < len(sys.argv):
                input_file = sys.argv[idx + 1]
            else:
                print("Erreur: -i nécessite un fichier.")
                sys.exit(1)
        if '-o' in sys.argv:
            idx = sys.argv.index('-o')
            if idx + 1 < len(sys.argv):
                output_file = sys.argv[idx + 1]
            else:
                print("Erreur: -o nécessite un fichier.")
                sys.exit(1)

        if input_file:
            if not os.path.exists(input_file):
                print(f"Erreur: Le fichier d'entrée '{input_file}' n'existe pas.")
                sys.exit(1)
            with open(input_file, 'r') as f:
                ciphertext = f.read()

        # Déchiffrer
        decrypted_text = ''
        try:
            from io import StringIO
            # Capture l'output de la fonction decrypt
            import contextlib

            with contextlib.redirect_stdout(StringIO()) as f:
                decrypt(key_file, ciphertext)
                decrypted_text = f.getvalue().strip()
        except Exception as e:
            print("Erreur lors du déchiffrement:", e)
            sys.exit(1)

        if output_file:
            with open(output_file, 'w') as f:
                f.write(decrypted_text)
        else:
            print(decrypted_text)

    else:
        print("Commande invalide.")
        print_help()
        sys.exit(1)

if __name__ == '__main__':
    main()
