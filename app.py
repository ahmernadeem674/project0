import os
import uuid
from datetime import datetime
from flask_migrate import Migrate
from flask import Flask, render_template, flash, redirect, request, session, url_for
from flask_sqlalchemy import SQLAlchemy

from ecg_detector.delineate_signal import read_ecg_recording
from forms import LoginForm, RegisterForm
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import Column, String


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SECRET_KEY'] = '!9m@S-dThyIlW[pHQbN^'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.debug=True
app.static_url_path='/static/'
app.config['UPLOAD_FOLDER'] = 'upload'
db = SQLAlchemy(app)
migrate = Migrate(app,db)


# Create User Model which contains id [Auto Generated], name, gender, age, username,  and password

class User(db.Model):

    __tablename__ = 'usertable'

    id = db.Column(db.Integer, primary_key=True)
    name= db.Column(db.String(15), unique=True)
    gender = db.Column(db.String(10), unique=False)
    age= db.Column(db.Integer, unique=False)
    username = db.Column(db.String(15), unique=True)
    password = db.Column(db.String(256), unique=True)


class FileScan(db.Model):
    id = Column(String(200),primary_key=True)
    name = Column(String(400))
    status = Column(String(100))
    created = Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('usertable.id'), nullable=False)


# User Registration Api End Point
@app.route('/', methods = ['GET', 'POST'])
def register():
    # Creating RegistrationForm class object
    form = RegisterForm(request.form)

    # Cheking that method is post and form is valid or not.
    if request.method == 'POST' and form.validate():

        # if all is fine, generate hashed password
        hashed_password = generate_password_hash(form.password.data, method='sha256')

        # create new user model object
        new_user = User(
            name = form.name.data,
            gender = form.gender.data,
            age = form.age.data,
            username = form.username.data,
            password = hashed_password )

        # saving user object into data base with hashed password
        db.session.add(new_user)

        db.session.commit()

        flash('You have successfully registered', 'success')

        # if registration successful, then redirecting to login Api
        return redirect(url_for('login'))

    else:

        # if method is Get, than render registration form
        return render_template('register.html', form = form)

# Login API endpoint implementation
@app.route('/login/', methods = ['GET', 'POST'])
def login():
    # Creating Login form object
    form = LoginForm(request.form)
    # verifying that method is post and form is valid
    if request.method == 'POST' and form.validate:
        # checking that user is exist or not by email
        user = User.query.filter_by(username = form.username.data).first()

        if user:
            # if user exist in database than we will compare our database hased password and password come from login form
            if check_password_hash(user.password, form.password.data):
                # if password is matched, allow user to access and save email and username inside the session
                flash('You have successfully logged in.', "success")

                session['logged_in'] = True
                session['user_id'] = user.id
                # After successful login, redirecting to home page
                return redirect(url_for('index'))
            else:
                # if password is in correct , redirect to login page
                flash('Username or Password Incorrect', "Danger")
                return redirect(url_for('login'))
    # rendering login page
    return render_template('login.html', form = form)
@app.route('/index/')
def index():
    return render_template('index.html')

@app.route('/logout/')
def logout():
    # Removing data from session by setting logged_flag to False.
    session['logged_in'] = False
    # redirecting to home page
    return render_template('logout.html')

@app.route('/records/', methods=['POST', 'GET'])
def records():
    if "logged_in" in session and session['logged_in']:
        data = []
        for instance in db.session.query(FileScan).filter(FileScan.user_id == session["user_id"]).order_by(FileScan.id):
            data.append({
                "Name": instance.name,
                "id": instance.id,
                "Time": instance.created,
                "Status": instance.status
            }, )
        return render_template('records.html', data=data, title='Latest Recordings')
    else:
        return redirect(url_for('login'))

@app.route('/ecg-finding/', methods=['POST', 'GET'])
def ecg_finding():
    if "logged_in" in session and session['logged_in']:
        result = None
        if request.method == "POST":
            file = request.files['event_file']
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))
            event_file_name = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)

            file = request.files['hea_file']
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))
            hea_file_name = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)

            file = request.files['dat_file']
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))
            dat_file_name = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)

            ecg_findings = read_ecg_recording(event_file_name.replace(".event", ""),
                                              dat_file_name.replace(".dat", ""))
            result = dict()
            result["ecg_findings"] = ecg_findings

            uuidOne = uuid.uuid1()
            time = datetime.now()
            scan_record = FileScan(id=str(uuidOne), name=os.path.basename(dat_file_name).replace(".dat", ""), created=time,
                                   status=ecg_findings, user_id=session["user_id"])
            db.session.add(scan_record)
            db.session.commit()
        return render_template('ecg-finding.html', result=result)
    else:
        return redirect(url_for('login'))

app.run(host='127.0.0.2')
