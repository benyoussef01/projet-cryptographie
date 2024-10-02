# Tapez le code principal
"""*********************************** 

Nom Programme : Exercice N 

Auteurs : 

  Ali BenYoussef     

  Ala Borgi     

Classe : CII-2-SIIR-A 
***********************************"""
import MaBiB

def MenuPrincipal():
    while True:
        print("-------| Application Multi Taches |-------")
        print("A- Enregistrement")
        print("B- Authentification")
        print("C- Quitter")
        choixMenuPr = input("Choisissez une option du Menu Principal : ")

        if choixMenuPr == "A":
            MaBiB.MenuA()
        elif choixMenuPr == "B":
            while True:
                print("Vous avez choisi l'option B - Authentification")
                print("B1- Hachage")
                print("B2- Chiffrement")
                print("R- Retour au Menu Principal")
                choixMenuB = input("Choisissez une option du Menu B : ")

                if choixMenuB == "B1":
                    MaBiB.MenuB1()
                elif choixMenuB == "B2":
                    MaBiB.MenuB2()
                elif choixMenuB == "R":
                    break
                else:
                    print("Option invalide. Veuillez choisir une option valide.")
        elif choixMenuPr == "C":
            break
        else:
            print("Option invalide. Veuillez choisir une option valide.")

if __name__ == "__main__":
    MenuPrincipal()
