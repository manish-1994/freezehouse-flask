import os
from dotenv import load_dotenv

load_dotenv(dotenv_path='.env', override=True)
print("Loaded MAIL_USERNAME =", os.getenv("MAIL_USERNAME"))

print("CWD =", os.getcwd()) 

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')

    TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
    TELEGRAM_CHAT_IDS = os.getenv("TELEGRAM_CHAT_IDS", "").split(',')
