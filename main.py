from dotenv import load_dotenv
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
import undetected_chromedriver as uc
import time
import tls_client
import json
import os
import re
import multiprocessing
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"

print(f"""{YELLOW}
=======================================
    PumpFun AutoComment Bot - V1
=======================================
Developed by: {CYAN}https://github.com/Akramelbahar{YELLOW}
For Fiverr Orders: {CYAN}https://www.fiverr.com/akramelbahar?{YELLOW}
=======================================
{RESET}""")

print(f"{BLUE}Please ensure your settings are configured in the .env file.{RESET}")
input(f"{CYAN}Press ENTER to continue...{RESET}\n")
load_dotenv()

PROXY_HOST = os.getenv("PROXY_HOST")
PROXY_PORT =  os.getenv("PROXY_PORT")
PROXY_USERNAME =  os.getenv("PROXY_USERNAME")
PROXY_PASSWORD = os.getenv("PROXY_PASSWORD")
CAPSOLVER_API_KEY = os.getenv("CAPSOLVER_API_KEY")  
COMMENT_TEXT = os.getenv("COMMENT_TEXT")
COMMENT_DELAY = int(os.getenv("COMMENT_DELAY"))
proxy = f"http://{PROXY_USERNAME}:{PROXY_PASSWORD}@{PROXY_HOST}:{PROXY_PORT}"
requests = tls_client.Session(client_identifier="chrome_120")
requests.proxies = {"http": proxy, "https": proxy}
BASE_URL = "https://api.mail.tm"
def capsolver_handler(html_content, target_url):
    """
    Handles AWS WAF CAPTCHA challenge using Capsolver.

    Args:
        html_content (str): The HTML content containing the challenge.
        target_url (str): The target URL where the CAPTCHA was encountered.

    Returns:
        str: The solved CAPTCHA token, or None if it fails.
    """
    print(f"{YELLOW}Extracting CAPTCHA challenge details...{RESET}")
    try:
        goku_props = extract_goku_props(html_content)
        if not goku_props:
            print("Failed to extract gokuProps.")
            return None

        print("Extracted gokuProps:", goku_props)

        challenge_js_url = extract_challenge_js_url(html_content)
        if not challenge_js_url:
            print("Failed to extract challenge.js URL.")
            return None

        print("Challenge JS URL:", challenge_js_url)

        captcha_solution = solve_captcha_with_capsolver(
            goku_props["key"], target_url
        )
        if not captcha_solution:
            print("Failed to solve CAPTCHA.")
            return None
        print(f"{GREEN}Extracted CAPTCHA Details Successfully.{RESET}")
        print("CAPTCHA Solved Successfully:", captcha_solution)
        return captcha_solution

    except Exception as e:
        print("Error handling CAPTCHA:", e)
        return None
def extract_goku_props(html):
    """Extract gokuProps (key, iv, context) from HTML."""
    match = re.search(r"window\.gokuProps\s*=\s*({[\s\S]+?});", html)
    if not match:
        return None

    props_str = match.group(1).replace("'", '"')
    props_str = re.sub(r'([{,])(\s*)(\w+):', r'\1"\3":', props_str)

    try:
        return json.loads(props_str)
    except json.JSONDecodeError:
        return None
def extract_challenge_js_url(html):
    """Extract challenge.js URL from the HTML."""
    match = re.search(r'src="(https://[^"]+?\.awswaf\.com/[^"]+?/challenge\.js)"', html)
    return match.group(1) if match else None
def solve_captcha_with_capsolver(site_key, page_url):
    """
    Solve the CAPTCHA using Capsolver API.

    Args:
        site_key (str): The site key for the CAPTCHA.
        page_url (str): The page URL where the CAPTCHA appears.

    Returns:
        str: The solved CAPTCHA token.
    """
    print("Submitting CAPTCHA to Capsolver...")
    payload = {
        "clientKey": CAPSOLVER_API_KEY,
        "task": {
            "type": "ReCaptchaV2TaskProxyless",
            "websiteURL": page_url,
            "websiteKey": site_key
        }
    }

    response = requests.post("https://api.capsolver.com/createTask", json=payload)
    if response.status_code != 200 or response.json().get("errorId") != 0:
        print("Error submitting to Capsolver:", response.json())
        return None

    task_id = response.json().get("taskId")
    print("Task submitted. Task ID:", task_id)

    for _ in range(30): 
        result_payload = {"clientKey": CAPSOLVER_API_KEY, "taskId": task_id}
        result = requests.post("https://api.capsolver.com/getTaskResult", json=result_payload)
        result_json = result.json()

        if result_json.get("status") == "ready":
            return result_json["solution"]["gRecaptchaResponse"]
        
        print("Waiting for CAPTCHA solution...")
        time.sleep(2)

    print("CAPTCHA solution timed out.")
    return None
def animate_text(text, delay=0.03):
    """Simulate typing animation for text."""
    for char in text:
        print(char, end="", flush=True)
        time.sleep(delay)
    print()

def format_token_data(data):
    """Format token data into a beautiful and animated display."""
    formatted = f"""
{'-'*40}
{'\033[92m'}**Token Details**{'\033[0m'}
{'-'*40}
{'\033[94m'}**Name**:{'\033[0m'} {data.get('name', 'N/A')}
{'\033[94m'}**Symbol**:{'\033[0m'} {data.get('symbol', 'N/A')}
{'\033[94m'}**Mint Address**:{'\033[0m'}
    {data.get('mint', 'N/A')}
{'\033[94m'}**Image**:{'\033[0m'}
    {data.get('image_uri', 'No image available')}
{'\033[94m'}**Description**:{'\033[0m'}
    {data.get('description', 'No description provided.')}
{'\033[94m'}**Metadata URI**:{'\033[0m'}
    {data.get('metadata_uri', 'N/A')}
{'\033[94m'}**Bonding Curve Address**:{'\033[0m'}
    {data.get('bonding_curve', 'N/A')}
{'\033[94m'}**Creator**:{'\033[0m'}
    {data.get('creator', 'N/A')}
{'\033[94m'}**Market Cap (USD)**:{'\033[0m'} ${data.get('usd_market_cap', 0.00):,.2f}
{'\033[94m'}**Total Supply**:{'\033[0m'} {data.get('total_supply', 'N/A')}
{'\033[94m'}**Real SOL Reserves**:{'\033[0m'} {data.get('real_sol_reserves', 'N/A')}
{'\033[94m'}**Real Token Reserves**:{'\033[0m'} {data.get('real_token_reserves', 'N/A')}
{'\033[92m'}{'-'*40}{'\033[0m'}
    """
    return formatted.strip()

def create_account():
    domain_response = requests.get(f"{BASE_URL}/domains").json()
    domain = domain_response['hydra:member'][0]['domain']

    email_address = f"test{int(time.time())}@{domain}"
    password = "secure_password"
    account_data = {"address": email_address, "password": password}
    account_response = requests.post(f"{BASE_URL}/accounts", json=account_data)

    if account_response.status_code == 201:
        print(f"Account created successfully: {email_address}")
        return email_address, password
    else:
        print("Error creating account:", account_response.json())
        return None, None
def authenticate(email, password):
    auth_data = {"address": email, "password": password}
    auth_response = requests.post(f"{BASE_URL}/token", json=auth_data)
    if auth_response.status_code == 200:
        token = auth_response.json()['token']
        print("Authenticated successfully.")
        return token
    else:
        print("Error authenticating:", auth_response.json())
        return None
def get_emails(token):
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{BASE_URL}/messages", headers=headers)
    if response.status_code == 200:
        return response.json()['hydra:member']
    else:
        print("Error fetching emails:", response.json())
        return []
"""email, password = create_account()
if email and password:
    token = authenticate(email, password)

    if token:
        print("\nWaiting for new emails...")

        while True:
            emails = get_emails(token)
            if emails:
                latest_email = emails[0]
                print("\nNew Email Received:")
                print(f"Subject: {latest_email['subject']}")
                otp = latest_email['subject'].split(" ")[0]
                print(otp)
                break
            time.sleep(1)"""
def cookies_inserter(driver, cookies):
    for key, value in cookies.items():
        driver.add_cookie({
            "name": key,
            "value": value,
            "domain": "pump.fun",  
            "path": "/"
        })  

class PumpFun:
    email = None
    user_id = None
    token = None
    identity_token = None
    cookies = None
    headers = {
                    "accept": "application/json",
                    "accept-encoding": "gzip, deflate, br, zstd",
                    "accept-language": "en-GB,en-US;q=0.9,en;q=0.8",
                    "content-type": "application/json",
                    "origin": "https://pump.fun",
                    "priority": "u=1, i",
                    "referer": "https://pump.fun/",
                    "privy-app-id": "cm1p2gzot03fzqty5xzgjgthq" , 
                    "sec-ch-ua": '"Google Chrome";v="120", "Chromium";v="120", "Not_A Brand";v="24"',
                    "sec-ch-ua-mobile": "?1",
                    "sec-ch-ua-platform": '"Android"',
                    "sec-fetch-dest": "empty",
                    "sec-fetch-mode": "cors",
                    "sec-fetch-site": "same-site",
                    "user-agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
                }
    offset = 0
    limit = 50
    BASE_URL = "https://privy.pump.fun/api/v1"
    HEADERS = {
        "accept": "application/json",
        "content-type": "application/json",
        "privy-app-id": "cm1p2gzot03fzqty5xzgjgthq",
        "origin": "https://privy.pump.fun",
        "referer": "https://privy.pump.fun/",
    }
    def __init__(self):
        pass
    def createAccount(self):
        print(f"{BLUE}Creating account...{RESET}")
        self.email, password = create_account()
        url = "https://privy.pump.fun/api/v1/passwordless/init"
        payload = {"email":f"{self.email}"}
        resp = requests.post(url , headers=self.headers , json=payload)
        print(resp.text)
        print(resp.status_code)
        if(resp.status_code != 200):
            raise Exception("Error during sending the code")
            return 
        token = authenticate(self.email, password)
        if token:
            print("\nWaiting for new emails...")

            while True:
                emails = get_emails(token)
                if emails:
                    latest_email = emails[0]
                    print("\nNew Email Received:")
                    print(f"Subject: {latest_email['subject']}")
                    otp = latest_email['subject'].split(" ")[0]
                    
                    break
        url = "https://privy.pump.fun/api/v1/passwordless/authenticate"
        payload = {"email":self.email,"code":otp,"mode":"login-or-sign-up"}
        resp = requests.post(url , headers=self.headers , json=payload)
        print(f"{GREEN}Account Created: {self.email}{RESET}")
        self.user_id = resp.json()["user"]["id"]
        self.token = resp.json()["token"]
        self.identity_token = resp.json()["identity_token"]
        self.cookies = resp.cookies
        print("Account Authenticated:", resp.json())
    def AccountFinalizer(self):
        options = uc.ChromeOptions()
        options.add_argument("--disable-blink-features=AutomationControlled")
        driver = uc.Chrome(options=options)
        url = "https://pump.fun/board"
        driver.get(url)
        try:
            WebDriverWait(driver, 30).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            print("Page loaded successfully.")
        except Exception as e:
            print("Page loading timed out:", str(e))
        while True :
            cookies_inserter(driver , self.cookies)
            driver.refresh()
            time.sleep(20)
            cookie = driver.get_cookie("auth_token")
            if cookie:
                print(f"Cookie '{cookie['name']}' exists with value: {cookie['value']}")
                break
            else:
                print("Cookie does not exist.")
        self.cookies = []
        co = []
        for cookie in driver.get_cookies():
            co.append({
                "name": cookie['name'],
                "value": cookie['value'],
                "domain": cookie.get('domain', ''),
                "path": cookie.get('path', '/'),
                "expiry": cookie.get('expiry', None)
            })    
        print(co)
        self.cookies = None
        cookies_str = "; ".join([f"{cookie['name']}={cookie['value']}" for cookie in co])
        self.headers["cookie"] = cookies_str
        driver.quit()
    def session(self):
        url = "https://privy.pump.fun/api/v1/sessions"
        payload = {"refresh_token":"deprecated"}
        resp = requests.post(url , headers=self.headers , json=payload)
        self.cookies = resp.cookies
        print(resp.text)
    def generateThreadToken(self):
        url = "https://frontend-api-v2.pump.fun/token/generateTokenForThread"
        resp = requests.get(url , headers=self.headers)
        print(resp.json())
        return resp.json()["token"]
    def comment(self, text, mintId, token):
        """
        Submit a comment to the pump.fun API.
        Handles CAPTCHA challenges by solving them and retrying the request.
        """
        GREEN = "\033[92m"
        YELLOW = "\033[93m"
        RED = "\033[91m"
        BLUE = "\033[94m"
        RESET = "\033[0m"

        url = "https://client-proxy-server.pump.fun/comment"
        payload = {"text": text, "mint": mintId}

       
        requests.proxies = {"http": proxy, "https": proxy}

        headers_copy = self.headers.copy()
        headers_copy["x-aws-proxy-token"] = token

        print(f"{BLUE}Submitting comment for Mint ID: {mintId}{RESET}")
        print(f"{YELLOW}Payload:{RESET} {payload}")

        response = requests.post(url, headers=headers_copy, cookies=self.cookies, json=payload)

        if response.status_code == 405:
            print(f"{RED}CAPTCHA challenge detected. Solving...{RESET}")
            target_url = "https://client-proxy-server.pump.fun/comment"
            solved_token = capsolver_handler(response.text, target_url)

            if solved_token:
                print(f"{GREEN}CAPTCHA Solved Successfully. Retrying request...{RESET}")

                refresh_url = "https://c41f1c23b6a1.a2e17e11.eu-south-2.token.awswaf.com/c41f1c23b6a1/voucher"
                refresh_payload = {
                    "captcha_voucher": solved_token,
                    "existing_token": self.cookies.get_dict().get("awswaf_session_storage")
                }

                refresh_response = requests.post(refresh_url, json=refresh_payload)

                if refresh_response.status_code == 200:
                    new_token = refresh_response.json().get("token")

                    self.cookies.set("awswaf_session_storage", new_token, domain=".pump.fun", path="/")
                    self.cookies.set("awswaf_token_refresh_timestamp", str(time.time() * 1000), domain=".pump.fun", path="/")

                    print(f"{BLUE}Retrying comment for Mint ID: {mintId}...{RESET}")
                    self.comment(text, mintId, self.generateThreadToken())
                else:
                    print(f"{RED}Failed to refresh token after CAPTCHA.{RESET}")
            else:
                print(f"{RED}Failed to solve CAPTCHA. Retrying in 10 seconds...{RESET}")
                time.sleep(10)
                self.comment(text, mintId, self.generateThreadToken())

        elif response.status_code == 200:
            print(f"{GREEN}Comment submitted successfully for Mint ID: {mintId}!{RESET}")
        else:
            print(f"{RED}Unexpected error. Status code: {response.status_code}{RESET}")
            print(f"{YELLOW}Response:{RESET} {response.text}")
    def getCoins(self) :
        url = f"https://frontend-api-v2.pump.fun/coins/for-you?offset={self.offset}&limit={self.limit}&includeNsfw=false"
        resp = requests.get(url , headers=self.headers)
        if(resp.status_code == 200):
            self.offset = self.offset +self.limit
            return resp.json()

def accountProcessor(a:PumpFun):
    a.createAccount()
    a.AccountFinalizer()
    a.session()
    a.generateThreadToken()
    while True :
        for coin in a.getCoins():
            try :
                mint = coin["mint"]
                print(format_token_data(coin))
                a.comment(COMMENT_TEXT , mint ,a.generateThreadToken() )
                print(f"{YELLOW}SLEEPING:{COMMENT_DELAY}")
                time.sleep(COMMENT_DELAY)
            except Exception as e:
                print(e)
                pass 
if __name__ == "__main__":
    accountProcessor(PumpFun())