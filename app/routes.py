from flask import render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, current_user, login_required
from app.models import User
from app import db, app, bcrypt
from app.forms import LoginForm, RegistrationForm, EditProfileForm


@app.route('/')
@app.route('/index')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('User created successfully.')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('account', username=current_user.username))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('account', username=current_user.username))
        else:
            flash('Login failed.')
    return render_template('login.html', title='Login', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/account/<username>', methods=['GET', 'POST'])
@login_required
def account(username):
    form = EditProfileForm()
    user = User.query.filter_by(username=username).first_or_404()

    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        user.password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        db.session.commit()

        flash('Your changes have been saved.')
        return redirect(url_for('account', username=user.username))
    elif request.method == 'GET':
        form.username.data = user.username
        form.email.data = user.email

    return render_template('account.html', title='Account', username=user.username, form=form)



