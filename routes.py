from flask import Flask, render_template, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required , logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, DataRequired, Email, EqualTo, ValidationError
from flask_bcrypt import Bcrypt

app=Flask(__name__, static_url_path='/static')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.app_context().push()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(length=30), nullable=False, unique=True)
    email_address = db.Column(db.String(length=50), nullable=False, unique=True)
    password = db.Column(db.String(length=60), nullable=False)

class Loginform(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=1, max=20)])
    password = PasswordField(validators=[InputRequired(), Length(min=1, max=20)])
    submit = SubmitField("LOGIN")

class Registerform(FlaskForm):
    username = StringField(validators=[Length(min=2, max=30), DataRequired()])
    email_address = StringField(validators=[Email(), DataRequired()])
    password = PasswordField(validators=[Length(min=6), DataRequired()])
    confirm_password = PasswordField(validators=[EqualTo('password'), DataRequired()])
    submit = SubmitField("REGISTER")

    def validate_username(self,username):
        existing_user_username = User.query.filter_by(username = username.data).first()

        if existing_user_username:
            raise ValidationError(
                  "THAT USERNAME EXISTS!!.TRY NEW NAME"
            )
        
    def validate_email_address(self, email_address_to_check):
        email_address = User.query.filter_by(email_address=email_address_to_check.data).first()
        if email_address:
            raise ValidationError('EMAIL ADDRESS EXISTS!!.TRY NEW EMAIL')
        
@app.route('/')
def first_page():
    return render_template('first.html')


@app.route('/register', methods=['GET','POST'])
def register_page():
    form = Registerform()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username = form.username.data, password = hashed_password, email_address = form.email_address.data)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login_page'))
    
    if form.errors != {}:
        for err_msg in form.errors.values():
            flash(f'There was an error with creating a user : {err_msg}', category='danger')

    return render_template('register.html', form = form)


@app.route('/after', methods=['GET','POST'])
def after_login():
    return render_template('after.html')


@app.route('/login', methods=['GET','POST'])
def login_page():
    form = Loginform()
    
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('after_login'))
            
    return render_template('index.html', form = form)

if __name__ == '__main__':
    app.run(debug=True,port=4000)