import datetime
from app import app, db, bcrypt
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
    non_hormonal = db.Column(db.Boolean, nullable=False)
    triphasic = db.Column(db.Boolean, nullable=False)
    monophasic = db.Column(db.Boolean, nullable=False)
    progestin = db.Column(db.Boolean, nullable=False)
    registered_on = db.Column(db.DateTime, nullable=False)

    def __init__(self, first_name, last_name, email, password, dob, first_day, cycle_length, non_hormonal, triphasic, monophasic, progestin):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.password = bcrypt.generate_password_hash(
            password, app.config.get('BCRYPT_LOG_ROUNDS')
        ).decode()
        self.dob = dob
        self.first_day = first_day
        self.cycle_length = cycle_length
        self.non_hormonal = non_hormonal
        self.triphasic = triphasic
        self.monophasic = monophasic
        self.progestin = progestin
        self.registered_on = datetime.datetime.now()

    def serialize(self):
        return {
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.email,
            'password': self.password,
            'dob': self.dob,
            'first_day': self.first_day,
            'cycle_length': self.cycle_length,
            'non_hormonal': self.non_hormonal,
            'triphasic': self.triphasic,
            'monophasic': self.monophasic,
            'progestin': self.progestin
        }

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
    prog = db.Column(db.Integer, nullable=False)

    def __init__(self, est, prog):
        self.est = est
        self.prog = prog

    def serialize(self):
        return {
            'est': self.est,
            'prog': self.prog
        }

class BlacklistToken(db.Model):
    __tablename__ = 'blacklist_tokens'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String(500), unique=True, nullable=False)
    blacklisted_on = db.Column(db.DateTime, nullable=False)

    def __init__(self, token):
        self.token = token
        self.blacklisted_on = datetime.datetime.now()

    def __repr__(self):
        return '<id: token: {}'.format(self.token)

    @staticmethod
    def check_blacklist(auth_token):
        res = BlacklistToken.query.filter_by(token=str(auth_token)).first()
        if res:
            return True
        else:
            return False
