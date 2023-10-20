from bs4 import BeautifulSoup
import requests 
import time
import json

class DuoAuthenticator:
    """
    Returns a python session object that has authenticated past DUO mobile for University of Cincinnati
    """
    def __init__(self, verbose=False) -> None:
        print("Initializing Duo Request Data Aggregation Service...")
        self.verbose = verbose
        self.iframe_params = None
        self.iframe_payload = None
        self.auth_payload = None
        self.auth_payload_keys = [
            "sid",
            "akey",
            "txid",
            "response_timeout",
            "parent",
            "duo_app_url",
            "eh_service_url",
            "eh_download_link",
            "_xsrf",
            "is_silent_collection",
            "has_chromium_http_feature"
        ]

        self.push_payload = None
        self.push_status_payload = None

    def build_iframe_data(self, soup: BeautifulSoup):
        print("1. Grabbing duo iframe attributes")
        iframe_data = soup.find("iframe")
        self.iframe_params = {
            "tx":iframe_data.attrs["data-sig-request"].split(":")[0],
            "parent":"https://login.uc.edu" + iframe_data.attrs["data-post-action"],
            "v":"2.6"
        }

        self.iframe_payload = {
            "tx": self.iframe_params["tx"],
            "parent":self.iframe_params["parent"],
            "java_version":"",
            "flash_version": "",
            "client_hints":"eyJicmFuZHMiOlt7ImJyYW5kIjoiQ2hyb21pdW0iLCJ2ZXJzaW9uIjoiMTE4In0seyJicmFuZCI6IkJyYXZlIiwidmVyc2lvbiI6IjExOCJ9LHsiYnJhbmQiOiJOb3Q9QT9CcmFuZCIsInZlcnNpb24iOiI5OSJ9XSwiZnVsbFZlcnNpb25MaXN0IjpbeyJicmFuZCI6IkNocm9taXVtIiwidmVyc2lvbiI6IjExOC4wLjAuMCJ9LHsiYnJhbmQiOiJCcmF2ZSIsInZlcnNpb24iOiIxMTguMC4wLjAifSx7ImJyYW5kIjoiTm90PUE/QnJhbmQiLCJ2ZXJzaW9uIjoiOTkuMC4wLjAifV0sIm1vYmlsZSI6ZmFsc2UsInBsYXRmb3JtIjoibWFjT1MiLCJwbGF0Zm9ybVZlcnNpb24iOiIxNC4wLjAiLCJ1YUZ1bGxWZXJzaW9uIjoiMTE4LjAuMC4wIn0=",
            "is_user_verifying_platform_authenticator_available": True,
            "is_cef_browser":False,
            "is_ipad_os":False,
            "react_support":True
        }

    def build_auth_payload(self, soup: BeautifulSoup):
        print("2. Building authentication payload with iframe attributes")
        self.auth_payload = {k: soup.find("input", attrs={"name":k, "type":"hidden"}).attrs["value"] for k in self.auth_payload_keys}

    def build_push_payload(self):
        print("4. Building the duo push request payload")
        self.push_payload = {
        "sid":self.auth_payload["sid"],
        "device":"phone1", # TODO: This may vary depending on the user. Need to grab information about available devices
        "factor": "Duo Push",
        "days_out_of_date": 0,
        "days_to_block": None
    }
        
    def build_status_payload(self, r: requests.Response):
        self.push_status_payload = {
            "sid":self.push_payload["sid"],
            "txid":r.json()["response"]["txid"]
        }

    def generate_duo_auth_session(self, s: requests.Session, hook: requests.Response):
        #find txid and parent link inside iframe
        duo_page_soup = BeautifulSoup(hook.content, "html.parser")
        self.build_iframe_data(duo_page_soup)

        duo_auth_post = s.post("https://api-c9607b10.duosecurity.com/frame/web/v1/auth", params=self.iframe_params, data=self.iframe_payload)

        if self.verbose:
            print("Duo authentication post request to retrieve iframe")
            print(duo_auth_post.text, "\n\n")

        duo_form_soup = BeautifulSoup(duo_auth_post.content, "html.parser")
        self.build_auth_payload(duo_form_soup)

        print("3. Posting session authentication credentials to duo server")
        final_auth_post = s.post("https://api-c9607b10.duosecurity.com/frame/web/v1/auth?", params=self.iframe_params, data=self.auth_payload)

        if self.verbose:
            print("Response from server for authentication post:")
            print(final_auth_post.text)

        self.build_push_payload()

        send_push = s.post("https://api-c9607b10.duosecurity.com/frame/prompt", data=self.push_payload)
        
        if self.verbose:
            print("Push request server response:")
            print(send_push.text)

        print("5. Duo push sent, Waiting for authentication from end user")

        self.build_status_payload(send_push)
        initial_status = s.post("https://api-c9607b10.duosecurity.com/frame/status", data=self.push_status_payload)
        if self.verbose:
            print("Status post request server response: ")
            print(initial_status.text)

        if initial_status.json()["response"]["status_code"] != "pushed":
            print("Something went wrong... handing Session object back to user. See server response below:")
            print(initial_status.text)

        while True:
            get_status = s.post("https://api-c9607b10.duosecurity.com/frame/status", data=self.push_status_payload)
            if get_status.json()["response"]["result"] == "SUCCESS":
                print("SUCCESS!\nDUO AUTHENTICATED!")
                break
            if get_status.json()["response"]["result"] == "FAILURE":
                print("User denied Duo push authentication request, authentication failed")
                break
            time.sleep(2)
        
        print("Handing session back to user!")

        if self.verbose:
            print("Duo Authentication Session Request Params and Payloads:\n\n")
            print(json.dumps(self.__dict__, indent=4))
        return s

