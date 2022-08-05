from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from dotenv import load_dotenv
import os

load_dotenv()  # take environment variables from .env.

APP_SECRET_KEY = os.getenv("APP_SECRET_KEY")
PWD_HASH_METHOD = os.getenv("PWD_HASH_METHOD")
PWD_SALT_LENGTH = os.getenv("PWD_SALT_LENGTH")

app = Flask(__name__)

app.config['SECRET_KEY'] = APP_SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Flask-Login
login_manager = LoginManager()  # create an instance of the login manager object
login_manager.init_app(app)  # initialize the login manager with the app.


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


##CREATE TABLE IN DB
# class User(UserMixin, db.Model):
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


# Line below only required once, when creating DB.
# db.create_all()


@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        """check if email already exists and use flash message to notify the user"""
        if User.query.filter_by(email=request.form['email']).first():
            flash('User already exist. Please login.')
            return redirect(url_for('login'))
        # hash and salt password for secured storage into database
        hash_and_salted_pwd = generate_password_hash(password=request.form['password'], method=PWD_HASH_METHOD, salt_length=str(PWD_SALT_LENGTH))
        new_user = User(
            email=request.form['email'],
            password=hash_and_salted_pwd,
            name=request.form['name']
        )
        db.session.add(new_user)
        db.session.commit()

        # Log in and authenticate user
        login_user(new_user)

        return redirect(url_for('secrets'))
    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=['POST', 'GET'])
def login():
    """uses user's email to fetch user details from database.
    If user exists, the password is checked to allow or deny access"""
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        try:
            # find user by email
            user = User.query.filter_by(email=email).first()
            # check if stored password hash is equal to entered password hashed
            if not check_password_hash(user.password, password):
                flash("Incorrect Password. Please check and try again.")
                return redirect(url_for('login'))
            login_user(user)
            return redirect(url_for('secrets'))
        except AttributeError:
            flash("Email doesn't exist. Please check and try again or Register Now!!")
            return redirect(url_for('login'))
    return render_template("login.html", logged_in=current_user.is_authenticated)


@app.route('/secrets')
@login_required
def secrets():
    user_name = current_user.name
    return render_template("secrets.html", name=user_name, logged_in=True)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
def download():
    return send_from_directory('static/files', 'cheat_sheet.pdf')


if __name__ == "__main__":
    app.run(debug=True)
