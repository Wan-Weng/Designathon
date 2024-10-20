import os
from flask import Flask, redirect, request, session, url_for, render_template
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

app = Flask(__name__)

# OAuth 2.0 Client ID and Client Secret
CLIENT_ID = '60026771477-uq8re8mouqcevu9id5586i5u8lpfl5j4.apps.googleusercontent.com'
CLIENT_SECRET = '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'
REDIRECT_URI = 'http://127.0.0.1:5000/oauth2callback'  # Flask server callback URI

# Calendar API scope
SCOPES = ['https://www.googleapis.com/auth/calendar.readonly']

# Secret key for Flask session
app.secret_key = os.urandom(24)

@app.route('/')
def index():
    """Render the index page."""
    return render_template('index.html')  # Use your HTML template directly with Flask

@app.route('/authorize')
def authorize():
    """Redirect user to Google OAuth 2.0 authorization page."""
    flow = Flow.from_client_secrets_file(
        'credentials.json',  # Path to your credentials.json
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    authorization_url, state = flow.authorization_url(access_type='offline')
    session['state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    """Handle the callback from Google after user authorizes."""
    flow = Flow.from_client_secrets_file(
        'credentials.json',  # Path to your credentials.json
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    flow.fetch_token(authorization_response=request.url)

    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)

    return redirect(url_for('calendar'))

@app.route('/calendar')
def calendar():
    """Display the user's upcoming Google Calendar events."""
    if 'credentials' not in session:
        return redirect(url_for('authorize'))

    credentials = Credentials.from_authorized_user_info(session['credentials'])

    if credentials.expired and credentials.refresh_token:
        credentials.refresh(Request())

    # Use Google Calendar API to fetch events
    service = build('calendar', 'v3', credentials=credentials)
    events_result = service.events().list(
        calendarId='primary',
        timeMin='2024-01-01T00:00:00Z',  # Change this to your desired time range
        maxResults=10,
        singleEvents=True,
        orderBy='startTime'
    ).execute()

    events = events_result.get('items', [])
    return render_template('calendar.html', events=events)

def credentials_to_dict(credentials):
    """Convert credentials to a dictionary for storage in the session."""
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

if __name__ == '__main__':
    app.run(debug=True)
