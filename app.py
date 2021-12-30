from enum import unique
from os import name
from flask import Flask, render_template, redirect, url_for, request, flash
from flask.wrappers import Request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from sqlalchemy.orm import backref
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_manager, login_user, login_required, logout_user, current_user
from datetime import datetime, date 

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposetobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
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

    # def __init__(self, owner_id, date_added, truck_id, last_name, customer, loading, unloading, received, price, payment, debt, comment):
    #     self.owner_id = owner_id
    #     self.date_added = date_added
    #     self.truck_id = truck_id
    #     self.last_name = last_name
    #     self.customer = customer
    #     self.loading = loading
    #     self.unloading = unloading
    #     self.received = received
    #     self.price = price
    #     self.payment = payment
    #     self.debt = debt
    #     self.comment = comment


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=3, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=3, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=3, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=3, max=80)])


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/dashboard')
@login_required
def dashboard():
    rows = Routes.query.all()

    return render_template("dashboard.html", name=current_user.username, row=rows)


@app.route('/insert', methods=['POST'])
@login_required
def insert():

    if request.method == 'POST':
        owner_id = request.form['owner_id']
        #date_added = request.form['date_added'] date_added,
        truck_id = request.form['truck_id']
        last_name = request.form['last_name']
        customer = request.form['customer']
        loading = request.form['loading']
        unloading = request.form['unloading']
        received = request.form['received']
        price = request.form['price']
        payment = request.form['payment']
        debt = request.form['debt']
        comment = request.form['comment']

        my_route = Routes(owner_id=owner_id, truck_id=truck_id, last_name=last_name, customer=customer, loading=loading, unloading=unloading, 
                received=received, price=price, payment=payment, debt=debt, comment=comment)
        db.session.add(my_route)
        db.session.commit()

        flash("Route Inserted Successfully!")

        return redirect(url_for('dashboard'))

    return render_template('dashboard.html', name=current_user.username)


@app.route('/update', methods=['GET', 'POST'])
@login_required
def update():
    if request.method == 'POST':
        my_route = Routes.query.get(request.form.get('id'))
        my_route.owner_id = request.form['owner_id']
        # my_route.date_added = request.form['date_added']
        my_route.truck_id = request.form['truck_id']
        my_route.last_name = request.form['last_name']
        my_route.customer = request.form['customer']
        my_route.loading = request.form['loading']
        my_route.unloading = request.form['unloading']
        my_route.received = request.form['received']
        my_route.price = request.form['price']
        my_route.payment = request.form['payment']
        my_route.debt = request.form['debt']
        my_route.comment = request.form['comment']

        db.session.commit()
        flash("Route Updated Successfully!")

        return redirect(url_for('dashboard'))

    return render_template('dashboard.html', name=current_user.username)


@app.route('/delete-route/<id>/', methods=['GET', 'POST'])
@login_required
def delete_route(id):
    my_route = Routes.query.get(id)
    db.session.delete(my_route)
    db.session.commit()
    flash("Route Deleted Successfully!")

    return redirect(url_for('dashboard'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('dashboard'))

    return render_template('signup.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)