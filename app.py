# app.py
from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lab.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

class Equipment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    available = db.Column(db.Boolean, default=True)
    borrowed_by = db.Column(db.String(150), nullable=True)

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(50))
    equipment = db.Column(db.String(150))
    worker = db.Column(db.String(150))
    time = db.Column(db.String(100))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



@app.route('/')
def home():
    return redirect('/login')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect('/signup')
        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()
        flash('Account created, please login.', 'success')
        return redirect('/login')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect('/dashboard')
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    equipment = Equipment.query.all()
    return render_template('dashboard.html', equipment=equipment, user=current_user.username)

@app.route('/add', methods=['POST'])
@login_required
def add_equipment():
    name = request.form['name']
    db.session.add(Equipment(name=name))
    db.session.commit()
    return redirect('/dashboard')

@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    name = request.form['name']
    eq = Equipment.query.filter_by(name=name, available=True).first()
    if eq:
        eq.available = False
        eq.borrowed_by = current_user.username
        db.session.add(Log(action='Check Out', equipment=name, worker=current_user.username, time=str(datetime.now())))
        db.session.commit()
    return redirect('/dashboard')

@app.route('/checkin', methods=['POST'])
@login_required
def checkin():
    name = request.form['name']
    eq = Equipment.query.filter_by(name=name, borrowed_by=current_user.username).first()
    if eq:
        eq.available = True
        eq.borrowed_by = None
        db.session.add(Log(action='Check In', equipment=name, worker=current_user.username, time=str(datetime.now())))
        db.session.commit()
    return redirect('/dashboard')

@app.route('/log')
@login_required
def view_log():
    logs = Log.query.order_by(Log.time.desc()).all()
    return render_template('log.html', logs=logs)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')
@app.route('/test')
def test():
    return render_template('login.html')

if __name__ == '__main__':
    
    with app.app_context():
       db.create_all()

    app.run(debug=True)

