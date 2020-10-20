from flask import Flask, render_template, session, request, url_for, redirect, flash, abort, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import InputRequired, Email, Length, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
import os
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from datetime import datetime
from flask_bcrypt import Bcrypt
import secrets
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = '4u9ajdslkf02kaldsjfj0'
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


@app.before_request
def make_session_permanent():
    session.permanent = True


# Database Tables
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(40), unique=True)
    password = db.Column(db.String(80))
    posts = db.relationship('Post', backref='owner', lazy=True)
    bio_content = db.Column(db.String(1000))


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    caption = db.Column(db.String(100), nullable=False)
    picture = db.Column(db.String(20), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


# Forms
class SignupForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "Username"})
    email = StringField(validators=[InputRequired(), Length(min=4, max=40)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=40)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Sign up')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("That username already exists. Please choose a different one.")

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError("That email address belongs to different user. Please choose a different one.")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=40)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=40)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Log In')


class PostForm(FlaskForm):
    caption = TextAreaField(validators=[InputRequired(), Length(min=0, max=1000)], render_kw={"placeholder": "Caption"})
    picture = FileField("Picture", validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    submit = SubmitField("Upload Post")

@app.route('/dashboard')
@login_required
def dashboard():
    posts = Post.query.all()
    return render_template('dashboard.html', posts=posts, title='Dashboard')


@app.route('/', methods=['GET', 'POST'])
@app.route('/home', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def home():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for("dashboard"))
        flash('User does not exist or invalid password.')
    return render_template('home.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
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


def save_picture(form_picture):
    rand_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_name = rand_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/pictures', picture_name)
    form_picture.save(picture_path)


@app.route('/post', methods=['GET', 'POST'])
@login_required
def create_post():
    form = PostForm()

    if form.validate_on_submit():
        if form.picture.data:
            new_picture = save_picture(form.picture.data)
            form.picture.data = new_picture
        new_post = Post(caption=form.caption.data, picture=form.picture.data, owner=current_user)
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('create_post.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)
