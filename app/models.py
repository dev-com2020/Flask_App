from flask import current_app
from flask_login import UserMixin
from itsdangerous import Serializer
from werkzeug.security import generate_password_hash, check_password_hash

from . import db, login_manager


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __repr__(self):
        return '<Role %r>' % self.name


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    password_hash = db.Column(db.String(128))
    email = db.Column(db.String(64), unique=True, index=True)
    confirmed = db.Column(db.Boolean, default=False)

    def generate_confirmation_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.id}).decode('utf-8')

    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True

    @property
    def password(self):
        raise AttributeError('Nie można odczytać hasła')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User %r>' % self.username

def generate_reset_token(self,expiration=3600):
    s = Serializer(current_app.config['SECRET_KEY'], expiration)
    return s.dumps({'reset': self.id}).decode('utf-8')

def reset_password(token, new_password):
    s = Serializer(current_app.config['SECRET_KEY'])
    try:
        data = s.loads(token.encode('utf-8'))
    except:
        return False
    user = User.query.get(data.get('reset'))
    if user is None:
        return False
    user.password = new_password
    db.session.add(user)
    return True

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
