# Tapez le code principal
"""*********************************** 

Nom Programme : Exercice N 

Auteurs : 

  Ali BenYoussef    

  Ala Borgi    
Classe : CII-2-SIIR-A 
***********************************"""
import re
import hashlib
import getpass
from Crypto.Cipher import AES
import rsa
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def MenuA():
    print("Vous avez choisi l'option A - Enregistrement")
    

def MenuB1():
    print("Vous avez choisi l'option B1 - Hachage")
    

def MenuB2():
    print("Vous avez choisi l'option B2 - Chiffrement")
    

def MenuA():
    while True:
        print("--------| Menu A : Enregistrement |--------")
        print("A1- Sauvegarder Données utilisateur")
        print("A2- Lire Données utilisateur")
        print("A3- Revenir au menu principal")
        choixMenuA = input("Choisissez une option du Menu A : ")

        if choixMenuA == "A1":
            SauvegarderDonneesUtilisateur()
        elif choixMenuA == "A2":
            LireDonneesUtilisateur()
        elif choixMenuA == "A3":
            break
        else:
            print("Option invalide. Veuillez choisir une option valide.")

def SauvegarderDonneesUtilisateur():
    try:
        with open("Authentification.txt", "a") as file:
            id_user = input("Id_user : ")
            login = input("Login : ")
            pwd = input("Mot de passe : ")
            classe = input("Classe (CII-2-SIIR-A/B/C/D) : ")
            email = input("Email : ")
            

            if re.match(r"[^@]+@[^@]+\.[^@]+", email) and re.match(r"CII-2-SIIR-[A-D]", classe):
                file.write(f"Id_user: {id_user}\nLogin&pwd: {login}&{pwd}\nEmail: {email}\nClasse: {classe}\n\n")
                print("Données enregistrées avec succès.")
            else:
                print("Données invalides. Veuillez respecter le format de l'email et de la classe.")

    except Exception as e:
        print(f"Erreur lors de l'enregistrement des données : {e}")

def LireDonneesUtilisateur():
    try:
        with open("Authentification.txt", "r") as file:
            data = file.read()
            if data:
                print(data)
            else:
                print("Aucune donnée n'a été enregistrée.")

    except Exception as e:
        print(f"Erreur lors de la lecture des données : {e}")

def ChargerAuthentification():
    try:
        auth_dict = {}
        with open("Authentification.txt", "r") as file:
            lines = file.readlines()
            for i in range(0, len(lines), 5):
                login, pwd = lines[i + 1].strip().split("&")
                auth_dict[login] = pwd
        return auth_dict
    except Exception as e:
        print(f"Erreur lors de la lecture du fichier d'authentification : {e}")
        return {}

def MenuB():
    auth_dict = ChargerAuthentification()
    if not auth_dict:
        print("Le fichier d'authentification est vide. Veuillez vous enregistrer avant de continuer.")
        return

    login = input("Login : ")
    pwd = getpass.getpass("Mot de passe : ")

    if login in auth_dict and auth_dict[login] == pwd:
        print("Authentification réussie.")
        while True:
            print("--------| Menu B : Authentification |--------")
            print("B1- Hachage")
            print("B2- Chiffrement")
            print("B3- Revenir au menu principal")
            choixMenuB = input("Choisissez une option du Menu B : ")

            if choixMenuB == "B1":
                MenuB1()
            elif choixMenuB == "B2":
                MenuB2()
            elif choixMenuB == "B3":
                break
            else:
                print("Option invalide. Veuillez choisir une option valide.")
    else:
        print("Authentification échouée. Veuillez vous enregistrer avant de continuer.")

def MenuB1():
    print("Vous avez choisi l'option B1 - Hachage")
    
def MenuB2():
    print("Vous avez choisi l'option B2 - Chiffrement")


ListeM = ["Password", "azerty", "shadow", "hunter"]
ListeMD5 = []
ListeSHA256 = []
ListeBlake2b = []

def HacherMD5():
    global ListeMD5
    ListeMD5 = [hashlib.md5(word.encode()).hexdigest() for word in ListeM]
    print("ListeMD5:", ListeMD5)

def HacherSHA256():
    global ListeSHA256
    ListeSHA256 = [hashlib.sha256(word.encode()).hexdigest() for word in ListeM]
    print("ListeSHA256:", ListeSHA256)

def HacherBlake2b():
    global ListeBlake2b
    ListeBlake2b = [hashlib.blake2b(word.encode()).hexdigest() for word in ListeM]
    print("ListeBlake2b:", ListeBlake2b)

def CrackerHache(indice):
    try:
        mot_hache = ListeM[indice]
        if mot_hache in ListeMD5:
            print(f"Le mot haché a été trouvé dans la liste MD5, à l'indice {ListeMD5.index(mot_hache)}")
        elif mot_hache in ListeSHA256:
            print(f"Le mot haché a été trouvé dans la liste SHA256, à l'indice {ListeSHA256.index(mot_hache)}")
        elif mot_hache in ListeBlake2b:
            print(f"Le mot haché a été trouvé dans la liste Blake2b, à l'indice {ListeBlake2b.index(mot_hache)}")
        else:
            print("Le mot haché n'a pas été trouvé dans les listes.")
    except IndexError:
        print("L'indice est invalide.")
    except NameError:
        print("La variable ListeMH n'est pas définie.")
def MenuB1():
    global ListeMD5, ListeSHA256, ListeBlake2b, ListeM
    while True:
        print("--------| Menu B1 : Hachage |--------")
        print("B1-a Hacher un message par MD5")
        print("B1-b Hacher un message par SHA256")
        print("B1-c Hacher un message par Blake2b")
        print("B1-d Cracker un message Haché")
        print("B1-e Revenir au menu MenuB")
        choixMenuB1 = input("Choisissez une option du Menu B1 : ")

        if choixMenuB1 == "B1-a":
            HacherMD5()
        elif choixMenuB1 == "B1-b":
            HacherSHA256()
        elif choixMenuB1 == "B1-c":
            HacherBlake2b()
        elif choixMenuB1 == "B1-d":
            indice = int(input("Entrez l'indice du mot haché à craquer : "))
            CrackerHache(indice)
        elif choixMenuB1 == "B1-e":
            break
        else:
            print("Option invalide. Veuillez choisir une option valide.")

def MenuB2():
    while True:
        print("--------| Menu B2 : Chiffrement |--------")
        print("B2-a Cesar")
        print("B2-b Affine")
        print("B2-c RSA")
        print("B2-d Revenir au menu MenuB")
        choixMenuB2 = input("Choisissez une option du Menu B2 : ")

        if choixMenuB2 == "B2-a":
            MenuB2a()
        elif choixMenuB2 == "B2-b":
            MenuB2b()
        elif choixMenuB2 == "B2-c":
            MenuB2c()
        elif choixMenuB2 == "B2-d":
            break
        else:
            print("Option invalide. Veuillez choisir une option valide.")

def MenuB2a():
    print("--------| Menu B2a : Chiffrement de César |--------")
    print("B2-a1 Chiffrement message")
    print("B2-a2 Déchiffrement message")
    print("B2-a3 Revenir au menu MenuB2")
    choixMenuB2a = input("Choisissez une option du Menu B2a : ")

    if choixMenuB2a == "B2-a1":
        ChiffrementCesar()
    elif choixMenuB2a == "B2-a2":
        DechiffrementCesar()
    elif choixMenuB2a == "B2-a3":
        return
    else:
        print("Option invalide. Veuillez choisir une option valide.")

def ChiffrementCesar():
    message = input("Entrez le message à chiffrer : ").upper()
    cle = int(input("Entrez la clé de chiffrement (nombre entier) : "))

    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    resultat = ''
    
    for lettre in message:
        if lettre in alphabet:
            position = alphabet.index(lettre)
            nouvelle_position = (position + cle) % 26
            resultat += alphabet[nouvelle_position]
        else:
            resultat += lettre

    print("Message chiffré : " + resultat)

def DechiffrementCesar():
    message = input("Entrez le message à déchiffrer : ").upper()
    cle = int(input("Entrez la clé de déchiffrement (nombre entier) : "))

    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    resultat = ''
    
    for lettre in message:
        if lettre in alphabet:
            position = alphabet.index(lettre)
            nouvelle_position = (position - cle) % 26
            resultat += alphabet[nouvelle_position]
        else:
            resultat += lettre

    print("Message déchiffré : " + resultat)

def MenuB2b():
    print("--------| Menu B2b : Chiffrement Affine |--------")
    print("B2-b1 Chiffrement message")
    print("B2-b2 Déchiffrement message")
    print("B2-b3 Revenir au menu MenuB2")
    choixMenuB2b = input("Choisissez une option du Menu B2b : ")

    if choixMenuB2b == "B2-b1":
        ChiffrementAffine()
    elif choixMenuB2b == "B2-b2":
        DechiffrementAffine()
    elif choixMenuB2b == "B2-b3":
        return
    else:
        print("Option invalide. Veuillez choisir une option valide.")

def ChiffrementAffine():
    message = input("Entrez le message à chiffrer : ").upper()
    Ka = int(input("Entrez la clé Ka (nombre entier) : "))
    Kb = int(input("Entrez la clé Kb (nombre entier) : "))

    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    resultat = ''
    
    for lettre in message:
        if lettre in alphabet:
            position = alphabet.index(lettre)
            nouvelle_position = (Ka * position + Kb) % 26
            resultat += alphabet[nouvelle_position]
        else:
            resultat += lettre

    print("Message chiffré : " + resultat)

def DechiffrementAffine():
    message = input("Entrez le message à déchiffrer : ").upper()
    Ka = int(input("Entrez la clé Ka (nombre entier) : "))
    Kb = int(input("Entrez la clé Kb (nombre entier) : "))

    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    resultat = ''
    
    for lettre in message:
        if lettre in alphabet:
            position = alphabet.index(lettre)
            nouvelle_position = (pow(Ka, -1, 26) * (position - Kb)) % 26
            resultat += alphabet[nouvelle_position]
        else:
            resultat += lettre

    print("Message déchiffré : " + resultat)

def MenuB2c():
    while True:
        print("--------| Menu B2c : Chiffrement RSA |--------")
        print("B2-c1 Chiffrement message")
        print("B2-c2 Déchiffrement message")
        print("B2-c3 Signature")
        print("B2-c4 Vérification Signature")
        print("B2-c5 Revenir au menu MenuB2")
        choixMenuB2c = input("Choisissez une option du Menu B2c : ")

        if choixMenuB2c == "B2-c1":
            ChiffrementRSA()
        elif choixMenuB2c == "B2-c2":
            DechiffrementRSA()
        elif choixMenuB2c == "B2-c3":
            SignatureRSA()
        elif choixMenuB2c == "B2-c4":
            VerificationSignature()
        elif choixMenuB2c == "B2-c5":
            return
        else:
            print("l'operation choisi non valide")

def ChiffrementRSA():
    message = input("Entrez le message à chiffrer : ")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    
    with open("private_key.pem", "wb") as private_key_file:
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key_file.write(private_key_pem)

    with open("public_key.pem", "wb") as public_key_file:
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_file.write(public_key_pem)

    
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open("ciphertext.bin", "wb") as ciphertext_file:
        ciphertext_file.write(ciphertext)

    print("Message chiffré et clés sauvegardées.")

def DechiffrementRSA():
    try:
        
        with open("private_key.pem", "rb") as private_key_file:
            private_key = serialization.load_pem_private_key(
                private_key_file.read(),
                password=None
            )

        
        with open("ciphertext.bin", "rb") as ciphertext_file:
            ciphertext = ciphertext_file.read()

        
        message = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        print("Message déchiffré : ", message.decode())

    except FileNotFoundError:
        print("Fichiers de clé privée ou de message chiffré introuvables.")
    except ValueError:
        print("Échec du déchiffrement. Assurez-vous que la clé privée correspond au message chiffré.")

def SignatureRSA():
    message = input("Entrez le message à signer : ")

    try:
        
        with open("private_key.pem", "rb") as private_key_file:
            private_key = serialization.load_pem_private_key(
                private_key_file.read(),
                password=None
            )

        signature = private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        with open("signature.bin", "wb") as signature_file:
            signature_file.write(signature)

        print("Signature créée et sauvegardée.")

    except FileNotFoundError:
        print("Fichier de clé privée introuvable.")
    except ValueError:
        print("Échec de la création de la signature. Assurez-vous que la clé privée est correcte.")

def VerificationSignature():
    message = input("Entrez le message : ")
    signature_file = input("Entrez le nom du fichier de signature : ")

    try:
        
        with open("public_key.pem", "rb") as public_key_file:
            public_key = serialization.load_pem_public_key(
                public_key_file.read()
            )

       
        with open(signature_file, "rb") as signature_file:
            signature = signature_file.read()

        try:
            public_key.verify(
                signature,
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("La signature est valide.")
        except ValueError:
            print("La signature est invalide.")

    except FileNotFoundError:
        print("Fichier de clé publique introuvable.")
    except ValueError:
        print("Échec de la vérification de la signature. Assurez-vous que la clé publique est correcte.")


