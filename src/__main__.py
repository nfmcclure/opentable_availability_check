"""

date: 2021-12-24

author: nfmcclure @ github

script: __main__.py

purpose:  Scrape/ping/mimic opentable graphql API for open times on specified dates.

"""

import os
import re
import json
import time
import base64
import requests

from bs4 import BeautifulSoup
from datetime import timedelta, date
from email.message import EmailMessage

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

# If modifying these scopes, delete your previously saved credentials
# at ~/.credentials/gmail-python-quickstart.json
# SCOPES = "https://mail.google.com/"
CLIENT_SECRET_FILE = 'credentials.json'
APPLICATION_NAME = 'Gmail API Python Quickstart'

creds = None
if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())


def get_csrf_token(header):
    # Link to public webpage that we can send date requests from:
    link = 'https://www.opentable.com/r/splintered-wand-seattle?ref=1068'
    # Get HTML of page (will contain graphql csrf token we need)
    response = requests.get(link, headers=header)
    # Parse response to make searchable.
    csrf_soup = BeautifulSoup(response.text, 'html.parser')
    # Find all script tags:
    scripts = csrf_soup.findAll("script")
    # Get a script that has the csrf token in it:
    csrf_script = [x for x in scripts if '__CSRF_TOKEN__' in x.text][0]
    # Create a capture regex group
    csrf_re = re.compile('__CSRF_TOKEN__=\'([^\']+)\'')
    # Match for token:
    csrf_match = csrf_re.search(csrf_script.text)
    # Return token OR None:
    csrf_token = csrf_match.group(1) if csrf_match else None
    return csrf_token


def generate_dates(days=90):
    start_dt = date.today()
    return_dates = []
    weekends = [4, 5, 6]
    for n in range(days + 1):
        temp_date = start_dt + timedelta(days=n)
        if temp_date.weekday() in weekends:
            return_dates.append(temp_date.strftime('%Y-%m-%d'))
    return return_dates


def create_message(subject, message_text):
    """Create a message for an email.

    Args:
        sender: Email address of the sender.
        to: Email address of the receiver.
        subject: The subject of the email message.
        message_text: The text of the email message.

    Returns:
        An object containing a base64url encoded email object.
    """
    msg = EmailMessage()
    msg.set_content(message_text)
    msg['Subject'] = subject
    msg['From'] = 'your+from+emailt@gmail.com'
    msg['To'] = 'your+to+email@gmail.com'
    raw = base64.urlsafe_b64encode(msg.as_bytes())
    raw = raw.decode()
    return {'raw': raw}


def send_message(service, message):
    """Send an email message.

    Args:
        service: Authorized Gmail API service instance.
        user_id: User's email address. The special value "me"
        can be used to indicate the authenticated user.
        message: Message to be sent.

    Returns:
        Sent Message.
    """
    try:
        message = (service.users().messages().send(userId='nfmcclure@gmail.com', body=message)
                   .execute())
        print('Message Id: {}'.format(message['id']))
        return message
    except HttpError as e:
        print('An error occurred: {}'.format(e))


def main():
    ot_url = 'https://www.opentable.com/dapi/fe/gql'
    header = {
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'en-US,en;q=0.9',
        'content-length': '289',
        'content-type': 'application/json',
        'origin': 'https://www.opentable.com',
        'ot-page-group': 'rest-profile',
        'ot-page-type': 'restprofilepage',
        'referer': 'https://www.opentable.com/r/splintered-wand-seattle?ref=1068',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="96", "Google Chrome";v="96"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
        'x-csrf-token': '33a9d4a2-2a90-404c-be4c-73c77bd4b44e'
    }

    # Get CSRF Token
    csrf_token = get_csrf_token(header)
    # Update headers
    header.update({'x-csrf-token': csrf_token})

    # Create a sequence of date strings.
    dates = generate_dates(days=90)
    available_dates = []
    for d in dates:
        print('Checking availability on date: {}'.format(d))
        time.sleep(2.0)
        restaurant_id = 1062610
        payload = {"operationName": "RestaurantsAvailability",
                   "variables": {"onlyPop": False,
                                 "channel": "ALL",
                                 "requestNewAvailability": True,
                                 "forwardDays": 58,
                                 "requireTimes": True,
                                 "requireTypes": ["Standard", "Experience"],
                                 "restaurantIds": [restaurant_id],
                                 "date": d,
                                 "time": "19:00",
                                 "partySize": 2,
                                 "databaseRegion": "NA",
                                 "restaurantAvailabilityTokens": [],
                                 "loyaltyRedemptionTiers": []},
                   "extensions": {"persistedQuery": {"version": 1,
                                                     "sha256Hash": "55b189ad974cc410bc3c3806dfba757011866babcb67a9a8a9c86464b46e587c"}}}

        # Make POST for data:
        data = json.dumps(payload)
        response = requests.post(ot_url, headers=header, data=data)
        if response.status_code == 200:
            response_data = response.json()
            restuarant_availability = response_data['data']['availability']
            if restuarant_availability:
                print('Available on : {}'.format(d))
                available_dates.append(d)
            else:
                err = response_data.get('errors')
                if err:
                    print('ERR: server error: {}'.format(err[0].get('message')))
        else:
            print('ERR: non-200 status response: {} on date {}.'.format(response.status_code, d))

    if available_dates:
        email_date_msg = '\n'.join(available_dates)
        # Send email:
        service = build('gmail', 'v1', credentials=creds)
        message = create_message(subject='Splintered Wand Availability', message_text=email_date_msg)
        send_message(service, message)


if __name__ == "__main__":
    main()
