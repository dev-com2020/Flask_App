from flask import render_template, request, url_for, flash, redirect
from flask_login import login_required, login_user, logout_user, current_user

from . import auth
from .forms import LoginForm, RegistrationForm, ChangePasswordForm, PasswordResetForm, PasswordResetRequestForm
from .. import db
from ..email import send_mail
from ..models import User


@auth.before_app_request
def before_request():
    if current_user.is_authenticated and not current_user.confirmed and request.endpoint and request.blueprint != 'auth' \
            and request.endpoint != 'static':
        return redirect(url_for('auth.unconfirmed'))


@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymus or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            next = request.args.get('next')
            if next is None or not next.starstwith('/'):
                next = url_for('main.index')
            return redirect(next)
        flash('Niepoprawna nazwa lub hasło')
    return render_template('auth/login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Zostałeś wylogowany')
    return redirect(url_for('main.index'))


@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data.lower(),
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_mail(user.email, 'Potwierdź swoje konto', 'auth/email/confirm', user=user, token=token)
        flash('Wysłaliśmy email z potwierdzeniem rejestracji')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)


@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        db.session.commit()
        flash('Potwierdziłeś swoje konto!')
    else:
        flash('Potwierdzenie nieudane,lub zły link')
    return redirect(url_for('main.index'))


@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_mail(current_user.email, 'Potwierdź swoje konto', 'auth/email/confirm', user=current_user, token=token)
    flash('Nowe potwierdzenie zostało wysłane!')
    return redirect(url_for('main.index'))


@auth.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit.verify_password(form.old_password.data):
        current_user.password = form.password.data
        db.session.add(current_user)
        db.session.commit()
        flash('Nasze hasło zostało zmienione')
        return redirect(url_for('main.index'))
    else:
        flash('Niepoprawne hsało!')
    return render_template("auth/change_password.html", form=form)


@auth.route('/reset', methods=['GET', 'POST'])
def password_reset_request():
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user:
            token = user.generate_reset_token()
            send_mail(user.email,'Reset Twojego hasła',user=user,token=token)
        flash('Został wysłany email z instrukcją resetu hasła!')
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html', form=form)



@auth.route('/reset/<token>', methods=['GET', 'POST'])
def password_reset(token):
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = PasswordResetForm()
    if form.validate_on_submit():
        if User.reset_password(token, form.password.data):
            db.session.commit()
            flash('Twoje hasło zostało zmienione!')
            return redirect(url_for('auth.login'))
        else:
            return redirect(url_for('main.index'))
        return render_template('auth/reset_password.html', form=form)