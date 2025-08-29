import os
from dotenv import load_dotenv
import pyrebase
import firebase_admin
from firebase_admin import credentials, auth

load_dotenv()

#config from .env
pyrebase_config = {
    "apiKey": os.getenv("FIREBASE_API_KEY"),
    "authDomain": os.getenv("FIREBASE_AUTH_DOMAIN"),
    "projectId": os.getenv("FIREBASE_PROJECT_ID"),
    "storageBucket": os.getenv("FIREBASE_STORAGE_BUCKET"),
    "messagingSenderId": os.getenv("FIREBASE_MESSAGING_SENDER_ID"),
    "appId": os.getenv("FIREBASE_APP_ID"),
    "measurementId": os.getenv("FIREBASE_MEASUREMENT_ID"),
    "databaseURL": os.getenv("FIREBASE_DATABASE_URL")
}

firebase = pyrebase.initialize_app(pyrebase_config)
auth_client = firebase.auth()


#Admin SDK
cred = credentials.Certificate("firebase_admin.json")
firebase_admin.initialize_app(cred)
