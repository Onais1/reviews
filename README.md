The Skate Sanctuary - Roller Girl Gang Feedbak App

A robust FLask web app for collecting and managing customer feedback.

FEATURES:
- Robust user management (user and admin)
- Feedback submission
- Feedback engagement (like or dislike)
- Feedback management (admin privilege)
- Feedback sentiment analysis (good, bad, or mixed)
- Feedback export (download in CSV or XLS format)
- User registration and login
- Admin registration and login


INSTALLATION GUIDE:

Setup Instructions are as follows...

- Clone the repo (git):
or copy the folder to your local machine

-Set up a Venv:
I. python -m venv venv
II. source venv/bin/activate # On WindowsOS: venv\Script\activate

- Install Required Dependencies:
I. pip install -r requirements.txt

- IMPORTANT! - Run the Setup Script File:
(This script will create the database and apply mitigations.)
I. setup.py (python file)

- Run the App (from project root or any directory via bash):
I. Project root:
II. cd/path/to/com6023-project
III. flask run --debug

Any directory:
I. flask --app/path/to/com6023-project/app:app run --debug

WindowsOS example:
I. flask --app C:/path/to/com6023-project/app:app run --debug

Linux/MacOS example:
flask --app/home/user/com6023-project/app:app run --debug

Advisories:
- The data URI in app.py is set dynamically, so the app works on any machine.
- The instance directory contains the local database (reviews.db) and can not be committed to version control.
- If you encounter issues, double check you have Python 3.6+ version, SQLite, and all dependencies installed.
