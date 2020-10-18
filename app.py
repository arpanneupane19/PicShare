from flask import Flask, render_template, session, request, url_for, redirect, flash, abort, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import InputRequired, Email, Length, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
import os
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from datetime import datetime
from flask_bcrypt import Bcrypt
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = 'jfale!@#gys^&*(@jafd00193n'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = os.environ.get("EMAIL_BLOGGY")
app.config['MAIL_PASSWORD'] = os.environ.get("PASSWORD_BLOGGY")
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Database Tables
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(40), unique=True)
    password = db.Column(db.String(80))
    bio_content = db.Column(db.String(1000))



# Forms
class SignupForm(FlaskForm):
	username = StringField(validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "Username"})
	email = StringField(validators=[InputRequired(), Length(min=4, max=40)], render_kw={"placeholder": "Email"})
	password = PasswordField(validators=[InputRequired(), Length(min=4, max=40)], render_kw={"placeholder": "Password"})
	submit = SubmitField('Sign up')


class LoginForm(FlaskForm):
	username = StringField(validators=[InputRequired(), Length(min=4, max=40)], render_kw={"placeholder": "Username"})
	password = PasswordField(validators=[InputRequired(), Length(min=4, max=40)], render_kw={"placeholder": "Password"})
	submit = SubmitField('Log In')


@app.route('/dashboard')
@login_required
def dashboard():
	return render_template('dashboard.html')


@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def home():
	form = LoginForm()

	if form.validate_on_submit():
		user = User.query.filter_by(username=form.username.data).first()
		if user:
			if bcrypt.check_password_hash(user.password, form.password.data):
				login_user(user)
				return redirect(url_for('dashboard'))
	return render_template('home.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
def logout():
	logout_user()
	flash('You have been logged out.')
	return redirect(url_for('home'))


@app.route('/sign-up', methods=['GET', 'POST'])
def signup():
	form = SignupForm()

	if current_user.is_authenticated:
		return redirect(url_for('dashboard'))

	if form.validate_on_submit():
		hashed_password = bcrypt.generate_password_hash(form.password.data)
		new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
		db.session.add(new_user)
		db.session.commit()
		flash(f'Account has been created for {form.username.data}.')
		return redirect(url_for('home'))

	return render_template('signup.html', form=form)


if __name__ == '__main__':
	app.run(debug=True)