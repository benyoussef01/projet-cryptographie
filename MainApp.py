from tkinter import Label, Entry, Button, Tk, StringVar
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
                print("B3- Retour au Menu Principal")
                choixMenuB = input("Choisissez une option du Menu B : ")

                if choixMenuB == "B1":
                    MaBiB.MenuB1()
                elif choixMenuB == "B2":
                    MaBiB.MenuB2()
                elif choixMenuB == "B3":
                    break
                else:
                    print("Option invalide. Veuillez choisir une option valide.")
        elif choixMenuPr == "C":
            break
        else:
            print("Option invalide. Veuillez choisir une option valide.")

if __name__ == "__main__":
    MenuPrincipal()
