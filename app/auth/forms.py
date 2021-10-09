from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, Regexp, EqualTo
from wtforms import ValidationError

from ..models import User


class LoginForm(FlaskForm):
    email = StringField('E-mail', validators=[DataRequired(), Length(1, 64), Email()])
    password = PasswordField('Hasło', validators=[DataRequired()])
    remember_me = BooleanField('Zapamiętaj mnie')
    submit = SubmitField('Zaloguj')


class RegistrationForm(FlaskForm):
    email = StringField('E-mail', validators=[DataRequired(), Length(1, 64), Email()])
    username = StringField('Nazwa', validators=[DataRequired(), Length(1, 64),
                                                Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                                       'Użytkownik musi zawierać litery,cyfry kropki oraz znaki specjalne')])
    password = PasswordField('Hasło',
                             validators=[DataRequired(), EqualTo('password2', message='Hasła muszą być takie same')])
    password2 = PasswordField('Hasło', validators=[DataRequired()])
    submit = SubmitField('Zarejestruj')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data.lower()).first():
            raise ValidationError('Adres email już istnieje')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Nazwa użytkownika już istnieje')

class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Stare hasło', validators=[DataRequired()])
    password = PasswordField('Nowe hasło', validators=[DataRequired(),EqualTo('password2',message='Hasła muszą być identyczne.')])
    password2 = PasswordField('Potwierdź nowe hasło', validators=[DataRequired()])
    submit = SubmitField('Zmień hasło')

class PasswordResetRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(),Length(1,64), Email()])
    submit = SubmitField('Resetuj hasło!')

class PasswordResetForm(FlaskForm):
    password = PasswordField('Nowe hasło',validators=[DataRequired(), EqualTo('password2', message='Hasła muszą być identyczne.')])
    password2 = PasswordField('Potwierdź nowe hasło', validators=[DataRequired()])
    submit = SubmitField('Resetuj hasło')