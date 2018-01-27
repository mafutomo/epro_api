import datetime
from api import app, db, bcrypt
import jwt

class Users(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    first_name = db.Column(db.String(128), nullable=False)
    last_name = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    dob = db.Column(db.String(32), nullable=False)
    first_day = db.Column(db.Integer, nullable=False, default=1)
    cycle_length = db.Column(db.Integer, nullable=False, default=30)
    condom = db.Column(db.Boolean, nullable=False)
    copper = db.Column(db.Boolean, nullable=False)
    mirena = db.Column(db.Boolean, nullable=False)
    pill = db.Column(db.Boolean, nullable=False)
    mini_pill = db.Column(db.Boolean, nullable=False)
    other = db.Column(db.Boolean, nullable=False)
    registered_on = db.Column(db.DateTime, nullable=False)

    def __init__(self, first_name, last_name, email, password, dob, first_day, cycle_length, condom, copper, mirena, pill, mini_pill, other):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.password = bcrypt.generate_password_hash(
            password, app.config.get('BCRYPT_LOG_ROUNDS')
        ).decode()
        self.dob = dob
        self.first_day = first_day
        self.cycle_length = cycle_length
        self. condom = condom
        self.copper = copper
        self.mirena = mirena
        self.pill = pill
        self.mini_pill = mini_pill
        self.other = other
        self.registered_on = datetime.datetime.now()

    def encode_auth_token(self, user_id):
        try:
            payload = {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=600),
                'iat': datetime.datetime.utcnow(),
                'sub': user_id
            }
            return jwt.encode(
                payload,
                app.config.get('SECRET_KEY'),
                algorithm='HS256'
            )
        except Exception as e:
            return e

    @staticmethod
    def decode_auth_token(auth_token):
        try:
            payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
            is_blacklisted_token = BlacklistToken.check_blacklist(auth_token)
            if is_blacklisted_token:
                return 'Token blacklisted. Please log in again.'
            else:
                return payload['sub']

        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'
            
class Exercises(db.Model):
    __tablename__ = "exercises"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    exercise = db.Column(db.String(255), nullable=False)

    def __init__(self, name, description, exercise):
        self.name = name
        self.description = description
        self.exercise = exercise

class Hormones(db.Model):
    __tablename__ = "hormones"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    est = db.Column(db.Integer, nullable=False)
    test = db.Column(db.Integer, nullable=False)
    prog = db.Column(db.Integer, nullable=False)

    def __init__(self, est, test, prog):
        self.est = est
        self.test = test
        self.prog = prog
