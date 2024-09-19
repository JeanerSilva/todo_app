from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
print(os.getenv('SECRET_KEY'))
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
db = SQLAlchemy(app)

@app.after_request
def add_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'  # or 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Server'] = 'Custom-Server'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    if response.status_code == 200:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=()'
    response.headers['Server'] = 'Custom-Server' 
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'"
    return response

@app.before_request
def create_tables():
    db.create_all()

login_manager = LoginManager(app)
login_manager.login_view = 'login' 
login_manager.login_message_category = 'danger'

bcrypt = Bcrypt(app)

# Always put Routes at end
from todo_project import routes