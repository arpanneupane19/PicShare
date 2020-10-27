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
from PIL import Image
import secrets
import datetime
import flask_whooshalchemy as wa


app = Flask(__name__)
app.config['SECRET_KEY'] = '4u9ajdslkf02kaldsjfj0'
app.config['WHOOSH_BASE'] = 'whoosh'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_PICSHARE')
app.config['MAIL_PASSWORD'] = os.environ.get('PASSWORD_PICSHARE')
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
    __searchable__ = ['username']

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(40), unique=True)
    password = db.Column(db.String(80))
    profile_pic = db.Column(db.String(20), nullable=False, default='default.jpg')

    posts = db.relationship('Post', backref='owner', foreign_keys='Post.user_id', lazy='dynamic')

    sender = db.relationship('Message',
                                    foreign_keys='Message.sender_id',
                                    backref='sender', lazy='dynamic')
    receiver = db.relationship('Message',
                                        foreign_keys='Message.receiver_id',
                                        backref='receiver', lazy='dynamic')

    liked = db.relationship('LikePost', backref='liker', lazy='dynamic')

    follower = db.relationship('Follow',
                                    foreign_keys='Follow.follower_id',
                                    backref='follower', lazy='dynamic')
    following = db.relationship('Follow',
                                        foreign_keys='Follow.following_id',
                                        backref='following', lazy='dynamic')

    commenter = db.relationship('Comment', backref='commenter', lazy='dynamic')

    bio_content = db.Column(db.String(1000))

    def is_following(self, user):
        return Follow.query.filter(
            Follow.follower_id == self.id,
            Follow.following_id == user.id).count() > 0


    def has_liked_post(self, post):
        return LikePost.query.filter(
            LikePost.user_id == self.id,
            LikePost.post_id == post.id).count() > 0

            
    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    caption = db.Column(db.String(100), nullable=False)
    picture = db.Column(db.String(20), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    likes = db.relationship('LikePost', backref='liked', lazy='dynamic')
    comments = db.relationship('Comment', backref='comment', lazy='dynamic')



class LikePost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))



class Follow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    following_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    comment_id = db.Column(db.Integer, db.ForeignKey('post.id'))
    commenter_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    comment_body = db.Column(db.String(100))


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    body = db.Column(db.String(140))


# Forms
class SignupForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=15)], render_kw={"placeholder": "Username"})
    email = StringField(validators=[InputRequired(), Length(min=4, max=40)], render_kw={"placeholder": "Email"})
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
    submit = SubmitField('Upload Post')


class ForgotPassword(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "Enter your email"})
    submit = SubmitField('Submit')


class UpdateAccount(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email(message="Invalid Email"), Length(max=50)], render_kw={"placeholder": "example@gmail.com"})
    username = StringField("Username", validators=[InputRequired(), Length(min=4, max=15)])
    bio = TextAreaField('Bio', [Length(min=0, max=1000)])
    profile_pic = FileField("Picture", validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    submit = SubmitField('Update Account')


    def validate_username(self, username):
        if current_user.username != username.data:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError("That username already exists. Please choose a different one.")

    def validate_email(self, email):
        if current_user.email != email.data:
            email = User.query.filter_by(email=email.data).first()
            if email:
                raise ValidationError("That email address belongs to different user. Please choose a different one.")


class MessageForm(FlaskForm):
    message = TextAreaField(validators=[InputRequired(), Length(min=0, max=140)], render_kw={"placeholder": "Message"})
    send = SubmitField("Send")


class UpdatePost(FlaskForm):
    caption = TextAreaField(validators=[InputRequired(), Length(min=0, max=1000)], render_kw={"placeholder": "Update caption"})
    submit = SubmitField('Update Post')


class CommentForm(FlaskForm):
    comment = TextAreaField(validators=[InputRequired(), Length(min=0, max=100)], render_kw={"placeholder": "Add a comment..."})
    submit = SubmitField('Comment')


class SearchForm(FlaskForm):
    search_str = StringField(validators=[InputRequired(), Length(min=0, max=15)], render_kw={"placeholder": "Search"})


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    search_form = SearchForm()
    posts = Post.query.all()

    if search_form.validate_on_submit():
        pass


    return render_template('dashboard.html', search_form=search_form, posts=posts, title='Dashboard')




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


    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

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
        password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(password)
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash(f'Account has been created for {form.username.data}.')
        return redirect(url_for('home'))

    return render_template('signup.html', form=form)


def save_profile_pic(form_profile_pic):
    rand_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_profile_pic.filename)
    picture_name = rand_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_name)
    form_profile_pic.save(picture_path)

    output_size = (125, 125)
    i = Image.open(form_profile_pic)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_name




@app.route('/account', methods=['GET', 'POST'])
def account():
    posts = Post.query.filter_by(owner=current_user).all()
    post_total = 0
    for post in posts:
        post_total += 1

    form = UpdateAccount()
    if form.validate_on_submit():
        if form.profile_pic.data:
            picture_file = save_profile_pic(form.profile_pic.data)
            current_user.profile_pic = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        current_user.bio_content = form.bio.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
        form.bio.data = current_user.bio_content
    profile_pic = url_for('static', filename='profile_pics/' + current_user.profile_pic)
    return render_template('account.html', form=form, email=current_user.email, username=current_user.username, posts_num=post_total, profile_pic=profile_pic)

# Reset email
def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Forgot your password?',
                  sender='noreply@demo.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
    {url_for('reset_password', token=token, _external=True)}
If you did not make this request then simply ignore this email.
'''
    mail.send(msg)


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPassword()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_reset_email(user)
            flash('An email has been sent to the email address you entered.')
        if not user:
            flash('There is no account with that email address.')

    return render_template('forgot_password.html', form=form)


@app.route('/reset-password/<token>')
def reset_password(token):
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('forgot-password'))


def save_picture(form_picture):
    rand_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_name = rand_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/pictures', picture_name)
    form_picture.save(picture_path)
    return picture_name



@app.route('/post', methods=['GET', 'POST'])
@login_required
def create_post():

    form = PostForm()
    if form.validate_on_submit:
        if form.picture.data:
            new_pic = save_picture(form.picture.data)
            new_post = Post(caption=form.caption.data, picture=new_pic, owner=current_user)
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for('dashboard'))


    return render_template('create_post.html', form=form)


def delete_picture(post_picture):
    post_path = os.path.join(app.root_path, 'static/pictures', post_picture)
    os.remove(post_path)


@app.route('/delete/<int:post_id>', methods=['GET',"POST"])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.owner != current_user:
        abort(403)
    else:
        delete_picture(post.picture)
        for comment in post.comments:
            db.session.delete(comment)
        db.session.delete(post)
        db.session.commit()
        flash('Your post has been deleted and is not viewable by anyone.')
        return redirect(url_for('dashboard'))


@app.route('/update/<int:post_id>', methods=['GET','POST'])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)

    form = UpdatePost()
    if form.validate_on_submit():
        post.caption = form.caption.data
        db.session.commit()
        flash('Your post has been updated!')
        return redirect(url_for('dashboard'))
    elif request.method == 'GET':
        form.caption.data = post.caption
    return render_template('update_post.html', form=form, post=post)



@app.route('/post/<int:post_id>')
@login_required
def specific_post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('specific_post.html', post=post)


@app.route('/like/<int:post_id>/<action>')
@login_required
def like_action(post_id, action):
    post = Post.query.filter_by(id=post_id).first_or_404()
    if action == 'like':
        new_like = LikePost(liker=current_user, liked=post)
        db.session.add(new_like)
        db.session.commit()

    if action == 'unlike':
        like = LikePost.query.filter_by(liker=current_user, liked=post).delete()
        db.session.commit()

    
    return redirect(request.referrer)


@app.route('/comment/<int:post_id>', methods=['GET', 'POST'])
@login_required
def comment(post_id):
    post = Post.query.get_or_404(post_id)

    form = CommentForm()
    if form.validate_on_submit():
        new_comment = Comment(comment=post, commenter=current_user, comment_body=form.comment.data)
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('comment.html', form=form)


@app.route('/comments/<int:post_id>', methods=['GET', 'POST'])
def view_comments(post_id):
    post = Post.query.get_or_404(post_id)
    comments = Comment.query.filter_by(comment=post).all()
    return render_template('view_comments.html', comments=comments, post=post)


@app.route('/<action>/<username>', methods=['GET', 'POST'])
@login_required
def follow(action, username):
    user = User.query.filter_by(username=username).first()
    if action == 'follow':
        if current_user.username == user.username:
            flash('You cannot follow yourself.')
            return redirect(url_for('dashboard'))
        follow = Follow(follower=current_user, following=user) # following=user not username because I spent one hour fixing this line lol.
        db.session.add(follow)
        db.session.commit()
        flash('following')
        return redirect(url_for('dashboard'))

    if action == 'unfollow':
        follow = Follow.query.filter_by(follower=current_user, following=user).delete()
        flash('Unfollowing')
        db.session.commit()
        return redirect(url_for('dashboard'))



       


@app.route('/users/<username>')
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()

    all_followers = Follow.query.filter_by(following=user).all()
    total = 0
    for i in all_followers:
        total += 1
    return render_template('user.html', user=user, total=total)



@app.route('/message/<receiver>', methods=['GET', "POST"])
@login_required
def message(receiver):
    user = User.query.filter_by(username=receiver).first_or_404()
    form = MessageForm()
    if receiver == current_user.username:
        return redirect(url_for('dashboard'))


    if form.validate_on_submit():
        message = Message(sender=current_user, receiver=user, body=form.message.data)
        db.session.add(message)
        db.session.commit()

        if db.session.commit():
            return redirect(request.url)

    messages_received = Message.query.filter_by(sender=user, receiver=current_user).all()
    messages_sent = Message.query.filter_by(sender=current_user, receiver=user).all()


    return render_template('message.html', form=form, user=user, messages_received=messages_received, messages_sent=messages_sent)





if __name__ == '__main__':
    app.run(debug=True)