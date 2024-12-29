from flask import Flask, request, jsonify
import os
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import re
from base64 import urlsafe_b64decode
import pyodbc

app = Flask(__name__)

# Gmail API Scopes
SCOPES = [
    "https://www.googleapis.com/auth/gmail.labels",
    "https://mail.google.com/",
    "https://www.googleapis.com/auth/gmail.modify",
]

def load_credentials():
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                "credentials.json", SCOPES
            )
            creds = flow.run_local_server(port=0)
        with open(r"token.json", "w") as token:
            token.write(creds.to_json())
    return creds

def extract_email_addresses(raw_addresses):
    """
    Extract email addresses enclosed in <> from a raw string of email addresses.
    """
    # Regular expression to match content inside <>
    email_pattern = r"<([^>]+)>"
    matches = re.findall(email_pattern, raw_addresses)
    return matches if matches else [raw_addresses]

def list_emails_without_label(service):

    query = "NOT label:MaliciousURL AND NOT label:Safe"
    try:
        listMail = []
        results = service.users().messages().list(userId="me", q=query).execute()
        messages = results.get("messages", [])

        if not messages:
            return {"messages": listMail}

        for message in messages:
            message_id = message["id"]
            tmp = get_email_details(service, message_id)
            listMail.append(tmp)
        return {"messages": listMail}

    except HttpError as error:
        return {"error": str(error)}

def get_email_details(service, message_id):
    """Get details of an email using its message ID."""
    try:
        message = service.users().messages().get(userId="me", id=message_id).execute()
        data = {"header": {}, "body": {}, "message_id": message_id}
        data["header"]["subject"] = get_header(message, 'Subject')
        data["header"]["from"] = extract_email_addresses(get_header(message, 'From'))
        data["header"]["to"] = extract_email_addresses(get_header(message, 'To'))
        data["header"]["date"] = get_header(message, 'Date')

        index = 0
        firstIndex = None
        
        if("parts" in message["payload"]["parts"][0]):
            if(len(message["payload"]["parts"][0]["parts"]) > 1):
                index = 1
            else:
                index = 0
            firstIndex = 0
        else:
            if(len(message["payload"]["parts"]) > 1):
                index = 1
            else:
                index = 0

        if firstIndex != None:
            raw_body = message["payload"]["parts"][firstIndex]["parts"][index]["body"]["data"]
            decoded_body = urlsafe_b64decode(raw_body).decode("utf-8", errors="ignore")
            data["body"]["content"] = decoded_body
        else:
            raw_body = message["payload"]["parts"][index]["body"]["data"]
            decoded_body = urlsafe_b64decode(raw_body).decode("utf-8", errors="ignore")
            data["body"]["content"] = decoded_body
        return data

    except HttpError as error:
        return {"error": str(error)}

def get_header(message, header_name):
    """Extract header value by name."""
    headers = message["payload"]["headers"]
    for header in headers:
        if header["name"] == header_name:
            return header["value"]
    return f"No {header_name}"

@app.route("/getEmails", methods=["POST"])
def webhook_emails():

    data = request.json
    usernamePost = data.get('username')
    passwordPost = data.get('password')

    if(usernamePost != "admin" or passwordPost != "admin"):
        return jsonify({"error": "Wrong username or password"}), 400
    try:
        creds = load_credentials()
        service = build("gmail", "v1", credentials=creds)
        emails = list_emails_without_label(service)
        return jsonify(emails)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/label_email', methods=['POST'])
def label_email():
    data = request.json
    usernamePost = data.get('username')
    passwordPost = data.get('password')
    type = data.get('type')
    email_id = data.get('email_id')

    if(usernamePost != "admin" or passwordPost != "admin"):
        return jsonify({"error": "Wrong username or password"}), 400
    
    if not email_id :
        return jsonify({"error": "Message-ID are required"}), 400
    try:
        creds = load_credentials()
        service = build("gmail", "v1", credentials=creds)
        if type == "malicious":
            body = {
                "addLabelIds": ["id_1"]
            }
        else:
            body = {
                "addLabelIds": ["id_2"]
            }
        service.users().messages().modify(
            userId="me", id=email_id, body=body
        ).execute()

        return jsonify({"status": f"Label Phishing added to email with Email-ID {email_id}"}), 200

    except HttpError as error:
        return jsonify({"error": f"An error occurred: {error}"}), 500
    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
