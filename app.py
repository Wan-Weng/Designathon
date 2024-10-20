import os
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
from flask import Flask, redirect, request, session, url_for, render_template
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

app = Flask(__name__)

# OAuth 2.0 Client ID and Client Secret (from your Google Cloud Console)
CLIENT_ID = '60026771477-uq8re8mouqcevu9id5586i5u8lpfl5j4.apps.googleusercontent.com'
CLIENT_SECRET = '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'
REDIRECT_URI = 'https://c4d8-68-204-144-235.ngrok-free.app/oauth2callback'

# Google Calendar API scope
SCOPES = ['https://www.googleapis.com/auth/calendar.readonly']

# Flask session secret key
app.secret_key = os.urandom(24)

@app.route('/')
def index():
    """Home page with a button to authorize Google Calendar access."""
    return render_template('index.html')

@app.route('/authorize')
def authorize():
    """Redirect the user to Google OAuth 2.0 authorization page."""
    flow = Flow.from_client_secrets_file(
        'credentials.json',  # Path to your credentials.json
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    authorization_url, state = flow.authorization_url(
        access_type='offline',    # Ensure that we get a refresh_token
        prompt='consent'          # Forces Google to show the consent screen every time
    )
    session['state'] = state
    return redirect(authorization_url)


@app.route('/oauth2callback')
def oauth2callback():
    """Handle the callback from Google after user authorizes."""
    try:
        flow = Flow.from_client_secrets_file(
            'credentials.json',
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI
        )
        flow.fetch_token(authorization_response=request.url)

        credentials = flow.credentials
        session['credentials'] = credentials_to_dict(credentials)

        return redirect(url_for('calendar'))
    except Exception as e:
        print(f"Error in oauth2callback: {str(e)}")  # Print the error to console
        return str(e), 500  # Return the error message in the response

@app.route('/calendar')
def calendar():
    """Display the user's upcoming Google Calendar events."""
    if 'credentials' not in session:
        return redirect(url_for('authorize'))

    credentials = Credentials.from_authorized_user_info(session['credentials'])

    # Check if credentials contain the required fields for refreshing tokens
    if credentials.refresh_token is None or credentials.token_uri is None:
        # Redirect to authorize if necessary fields are missing
        return redirect(url_for('authorize'))

    # Check if credentials have expired
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


@app.route('/clear_session')
def clear_session():
    """Clear the session to reset stored tokens."""
    session.clear()
    return "Session cleared!", 200

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
