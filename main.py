import requests
import DuoAuthenticator
import json

payload = {
    "root": {
        "locations": [
            {
                "room_id": 2612
            }
        ],
        "dates": [
            {
                "start_dt": "2023-10-24T14:00:00",
                "end_dt": "2023-10-24T16:00:00",
                "occ_id": 1
            }
        ]
    }
}
s = requests.session()
duo_data = DuoAuthenticator.DuoAuthenticator(verbose=True)
#invoke a new login session by making a request that requires authentication
get_session = s.post("https://25live.collegenet.com/25live/data/uc/run/event/quotas/check.json?caller=pro-EventQuotaService.check", data=payload, params={"caller":"pro-EventQuotaService.check"})
user_creds = None

#post login data
with open("private_credentials.json", "r") as f:
    user_creds = json.load(f)
    login = s.post(get_session.url, data={"j_username":user_creds["j_username"], "j_password":user_creds["j_password"], "_eventId_proceed":""})

duo_data.generate_duo_auth_session(s, login)