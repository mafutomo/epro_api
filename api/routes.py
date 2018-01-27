from flask import request, make_response, jsonify, abort
from api.models import Users
from api import app, db, bcrypt


@app.route('/')
def index():
	return "EPRO BACKEND"
