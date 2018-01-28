from flask import request, make_response, jsonify, abort
from api.models import Users, Hormones, BlacklistToken, Exercises
from api import app, db, bcrypt


@app.route('/')
def index():
	return "EPRO BACKEND"

@app.route('/users/all', methods=['GET'])
def get_users():
	users = Users.query.order_by(Users.id).all()
	return jsonify({'users': [Users.serialize(user) for user in users]})

@app.route('/users/<int:id>', methods=['GET'])
def get_user(id):
	user = Users.query.get(id)
	if not user:
		abort(400)
	return jsonify(Users.serialize(user))

@app.route('/users/register', methods=['POST'])
def register():
	post_data = request.get_json()

	if email is None or password is None:
		responseObject = {
			'status': 'error',
			'message': 'Invalid input.'
		}
		return jsonify(responseObject), 400
	if Users.query.filter_by(email=email).first() is not None:
		responseObject = {
			'status': 'error',
			'message': 'User already exists.'
		}
		return jsonify(responseObject), 400
	user = Users(
		first_name = post_data.get('first_name'),
		last_name = post_data.get('last_name'),
		email = post_data.get('email'),
		password = post_data.get('password'),
		dob = post_data.get('dob'),
		first_day = post_data.get('first_day'),
		cycle_length = post_data.get('cycle_length'),
		non_hormonal = post_data.get('non_hormonal'),
		triphasic = post_data.get('triphasic'),
		monophasic = post_data.get('monophasic'),
		progestin = post_data.get('progestin')
	)
	db.session.add(user)
	db.session.commit()

	auth_token = user.encode_auth_token(user.id)
	responseObject = {
		'status': 'success',
		'message': 'Successfully registered',
		'auth_token': auth_token.decode()
	}
	return jsonify(responseObject), 201

@app.route('/auth/login', methods=['POST'])
def user_login():
	email = request.json.get('email')
	password = request.json.get('password')
	user = Users.query.filter_by(email=email).first()
	if user and bcrypt.check_password_hash(user.password, password):
		auth_token = user.encode_auth_token(user.id)
		if auth_token:
			responseObject = {
				'email': user.email,
				'status': 'success',
				'message': 'Successfully logged in.',
				'auth_token': auth_token.decode()
			}
			return jsonify(responseObject), 200
	else:
		responseObject = {
			'status': 'error',
			'message': 'Invalid login.'
		}
		return jsonify(responseObject), 404

@app.route('/auth/status', methods=['GET'])
def get_auth():
	auth_header = request.headers.get('Authorization')
	auth_token = auth_header.split(' ')[0]

	if auth_token:
		decoded = Users.decode_auth_token(auth_token)
		if isinstance(decoded, str):
			responseObject = {
			'status': 'error',
			'message': decoded
			}
			return jsonify(responseObject), 401
		else:
			user = Users.query.get(decoded)
			responseObject = {
				'status': 'success',
				'data': {
					'user_id': user.id,
					'email': user.email,
					'registered_on': user.registered_on
				}
			}
			return jsonify(responseObject), 200
	else:
		responseObject = {
			'status': 'error',
			'message': 'Invalid token.'
		}
		return jsonify(responseObject), 401

@app.route('/auth/logout', methods=['POST'])
def logout():
	auth_header = request.headers.get('Authorization')
	auth_token = auth_header.split(' ')[0]

	if auth_token:
		decoded = Users.decode_auth_token(auth_token)
		if isinstance(decoded, str):
			responseObject = {
				'status': 'error',
				'message': decoded
			}
			return jsonify(responseObject), 401
		else:
			blacklist_token = BlacklistToken(token=auth_token)
			db.session.add(blacklist_token)
			db.session.commit()
			responseObject = {
				'status': 'success',
				'message': 'Logged out.'
			}
			return jsonify(responseObject), 200
	else:
		responseObject = {
			'status': 'error',
			'message': 'Invalid token.'
		}
		return jsonify(responseObject), 403

@app.route('/hormones/all', methods=['GET'])
def get_hormones():
	horms = Hormones.query.order_by(Hormones.id).all()
	return jsonify({'hormones': [Hormones.serialize(horm) for horm in horms]})

@app.route('/hormones/<int:id>', methods=['GET'])
def get_hormone(id):
	horm = Hormones.query.get(id)
	if not horm:
		abort(400)
	return jsonify(Hormones.serialize(horm))