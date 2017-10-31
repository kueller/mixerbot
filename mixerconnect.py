import time
import json
import requests

API_URL = "https://mixer.com/api/v1"
CLIENT_ID = "1fbf85d13e1069482edfc0928761c3792c7dd28a61c5dfd8"

ROLES = ["chat:connect", "chat:chat", "chat:whisper", "chat:poll_start",
         "chat:timeout", "chat:purge", "chat:remove_message",
         "chat:clear_messages", "chat:giveaway_start"]

# Returns the single channel id of a user.
def get_channel_id(streamer):
    r = requests.get("%s/channels/%s?fields=id" % (API_URL, streamer))
    info = r.json()
    return info["id"]

# Returns the single user id of a user.
def get_user_id(user):
    r = requests.get("%s/channels/%s?fields=userId" % (API_URL, user))
    data = r.json()

    return data["userId"]

# Returns chat info JSON structure.
def get_chat_info(channel_id, header):
    r = requests.get("%s/chats/%s" % (API_URL, channel_id), headers=header)
    data = r.json()

    return data

# Returns boolean of stream online status.
def stream_is_online(streamer):
    channel_id = get_channel_id(streamer)
    r = requests.get("%s/channels/%s" % (API_URL, channel_id))
    return r.json()["online"]

# Uses shortcode authentication. Asks user to enter code on Mixer.
# Returns auth code if succesful, and an empty string if the code
# times out.
def short_auth():
    payload = {"client_id": CLIENT_ID,
               "scope": ' '.join(ROLES)}
    r = requests.post("%s/oauth/shortcode" % API_URL, data = payload)
    data = r.json()

    handle = data["handle"]
    code = data["code"]
    exp_time = int(data["expires_in"])

    print("This bot is currently not authenticated, or needs to be re-authenticated.")
    print("Authentication should only be required once per account.\n")
    print("Go to mixer.com/go and enter the code: %s\n" % code)

    for i in range(exp_time // 10):
        r = requests.get("%s/oauth/shortcode/check/%s" % (API_URL, handle))
        if r.status_code == 200:
            return r.json()["code"]
        time.sleep(10)

    print("Code expired, please try again")
    return ""

# Using the code from above, gets an access token.
# Returns the JSON data structure.
def get_access_token(code):
    payload = {"grant_type": "authorization_code",
               "client_id": CLIENT_ID,
               "code": code}
    r = requests.post("%s/oauth/token" % API_URL, data=payload)

    if r.status_code != 200:
        return None
    
    data = r.json()
    return data

# Same as above but for refreshing the access token.
def refresh_access_token(token):
    payload = {"grant_type": "refresh_token",
               "client_id": CLIENT_ID,
               "refresh_token": token}
    r = requests.post("%s/oauth/token" % API_URL, data=payload)

    if r.status_code != 200:
        return None
    
    data = r.json()
    return data
