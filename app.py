from flask import Flask, render_template, flash, request, redirect, url_for
from datetime import datetime 
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash 
from datetime import date
from webforms import LoginForm, PostForm, UserForm, PasswordForm, NamerForm, SearchForm
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from webforms import LoginForm, PostForm, UserForm, PasswordForm, NamerForm
from flask_ckeditor import CKEditor

# Create a Flask Instance
app = Flask(__name__)
# Add CKEditor
ckeditor = CKEditor(app)
# Add Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
# Secret Key!
app.config['SECRET_KEY'] = "my super secret key that no one is supposed to know"
# Initialize The Database
db = SQLAlchemy(app)

class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80), unique=True)
    routes = db.relationship('Routes', backref='owner')


class Routes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    date_added = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    truck_id = db.Column(db.Integer, nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    customer = db.Column(db.String(50), nullable=False)
    loading = db.Column(db.String(50), nullable=False)
    unloading = db.Column(db.String(50), nullable=False)
    received = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Integer, nullable=False)
    payment = db.Column(db.String(12), nullable=False)
    debt = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.String(100))

# Flask_Login Stuff
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
	return Users.query.get(int(user_id))

# Pass Stuff To Navbar
@app.context_processor
def base():
	form = SearchForm()
	return dict(form=form)

# Create Admin Page
@app.route('/admin')
@login_required
def admin():
	id = current_user.id
	if id == 1:
		return render_template("admin.html")
	else:
		flash("Sorry you must be the Admin to access the Admin Page...")
		return redirect(url_for('dashboard'))

# Create Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user = Users.query.filter_by(username=form.username.data).first()
		if user:
			# Check the hash
			if check_password_hash(user.password_hash, form.password.data):
				login_user(user)
				flash("Login Succesfull!!")
				return redirect(url_for('dashboard'))
			else:
				flash("Wrong Password - Try Again!")
		else:
			flash("That User Doesn't Exist! Try Again...")


	return render_template('login.html', form=form)