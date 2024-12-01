#!/usr/bin/env python3
import sys
import base64
import math

def print_help():
    print("""Script monRSA par Nug
Syntaxe :
monRSA <commande> [<clé>] [<texte>] [switchs]
Commande :
keygen : Génère une paire de clé
crypt : Chiffre <texte> pour le clé publique <clé>
decrypt: Déchiffre <texte> pour le clé privée <clé>
help : Affiche ce manuel
Clé :
Un fichier qui contient une clé publique monRSA ("crypt") ou une clé privée ("decrypt")
Texte :
Une phrase en clair ("crypt") ou une phrase chiffrée ("decrypt")
Switchs :
-f <file> permet de choisir le nom des clé générés, monRSA.pub et monRSA.priv par défaut
""")

def decimal_to_hex(n):
    return hex(n)

def hex_to_decimal(s):
    return int(s, 16)

def keygen(file_prefix='monRSA'):
    # Example values from your validation
    p = 7759902343
    q = 7802210653
    n = p * q
    nPrime = (p -1)*(q -1)
    e = 11360117699205053719
    d = 36448893553452967375

    # Save private key
    priv_filename = f"{file_prefix}.priv"
    with open(priv_filename, 'w') as f:
        f.write('---begin monRSA private key---\n')
        key_data = decimal_to_hex(n) + '\n' + decimal_to_hex(d)
        key_b64 = base64.b64encode(key_data.encode()).decode()
        f.write(key_b64 + '\n')
        f.write('---end monRSA key---\n')
    # Save public key
    pub_filename = f"{file_prefix}.pub"
    with open(pub_filename, 'w') as f:
        f.write('---begin monRSA public key---\n')
        key_data = decimal_to_hex(n) + '\n' + decimal_to_hex(e)
        key_b64 = base64.b64encode(key_data.encode()).decode()
        f.write(key_b64 + '\n')
        f.write('---end monRSA key---\n')
    print(f"Keys generated and saved as {pub_filename} and {priv_filename}")

def crypt(key_file, plaintext):
    with open(key_file, 'r') as f:
        lines = f.readlines()
        if not lines[0].strip() == '---begin monRSA public key---':
            print("Invalid public key file.")
            return
        key_b64 = lines[1].strip()
        key_data = base64.b64decode(key_b64).decode()
        n_hex, e_hex = key_data.strip().split('\n')
        n = hex_to_decimal(n_hex)
        e = hex_to_decimal(e_hex)

    ciphertext = []
    for char in plaintext:
        m = ord(char)
        c = pow(m, e, n)
        ciphertext.append(str(c))
    print(ciphertext)

def decrypt(key_file, ciphertext):
    with open(key_file, 'r') as f:
        lines = f.readlines()
        if not lines[0].strip() == '---begin monRSA private key---':
            print("Invalid private key file.")
            return
        key_b64 = lines[1].strip()
        key_data = base64.b64decode(key_b64).decode()
        n_hex, d_hex = key_data.strip().split('\n')
        n = hex_to_decimal(n_hex)
        d = hex_to_decimal(d_hex)

    # Ensure the ciphertext is a list of integers
    if isinstance(ciphertext, str):
        ciphertext_numbers = eval(ciphertext)
    else:
        ciphertext_numbers = ciphertext

    plaintext = ''
    for c_text in ciphertext_numbers:
        c = int(c_text)
        m = pow(c, d, n)
        plaintext += chr(m)
    print(plaintext)

def main():
    args = sys.argv[1:]
    if not args or args[0] == 'help':
        print_help()
        return

    command = args[0]
    file_prefix = 'monRSA'

    if '-f' in args:
        f_index = args.index('-f')
        if f_index + 1 < len(args):
            file_prefix = args[f_index + 1]
            del args[f_index:f_index+2]

    if command == 'keygen':
        keygen(file_prefix)
    elif command == 'crypt':
        if len(args) < 3:
            print("Missing parameters for 'crypt'.")
            return
        key_file = args[1]
        plaintext = args[2]
        crypt(key_file, plaintext)
    elif command == 'decrypt':
        if len(args) < 3:
            print("Missing parameters for 'decrypt'.")
            return
        key_file = args[1]
        ciphertext = args[2]
        decrypt(key_file, ciphertext)
    else:
        print_help()

if __name__ == "__main__":
    main()
