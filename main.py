import requests
import DuoAuthenticator
import json

s = requests.session()
duo_authenticate = DuoAuthenticator.DuoAuthenticator(verbose=False)

if __name__ == "__main__":
    # invoke a new login session by making a request that requires authentication
    get_catalyst = s.get("https://www.catalyst.uc.edu/")

    # store login data
    with open("private_credentials.json", "r") as f:
        user_creds = json.load(f)

    # all UC websites employ a post request that takes the user credentials as the payload, the response is the hook for duo mobile.
    login_hook = s.post(get_catalyst.url, data={"j_username":user_creds["j_username"], "j_password":user_creds["j_password"], "_eventId_proceed":""})
    
    # use the hook to send a duo push request
    duo_authenticate.generate_duo_auth_session(s, login_hook)