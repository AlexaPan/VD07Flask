from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db' #uses sqlite
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'secret'


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
logins_manager = LoginManager(app)
logins_manager.login_view = 'login'

from app import routes