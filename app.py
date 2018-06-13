from flask import Flask, request, jsonify, redirect, g
from flask_pymongo import PyMongo

from werkzeug.security import generate_password_hash, check_password_hash

from bson import json_util

from config import MONGO_URI
from auth import *


app = Flask(__name__)
app.config['MONGO_URI'] = MONGO_URI
app.config['DEBUG'] = True

app_context = app.app_context()
app_context.push()

mongo = PyMongo(app)

col_users = mongo.db.users
col_questions = mongo.db.questions
col_tokens = mongo.db.tokens        # refresh tokens


def authenticate(username, password):
    user = col_users.find_one({'username': username})
    if user and check_password_hash(user['password'], password):
        return user
    else:
        return None

@app.route('/signin', methods=['POST'])
def signin():
    data = request.get_json()
    user = authenticate(data['username'], data['password'])
    if user:
        token_payload = {'username': user['username']}
        access_token = create_access_token(token_payload)
        refresh_token = create_refresh_token(token_payload)
        col_tokens.insert_one({'value': refresh_token})
        return jsonify({'access_token': access_token, 
                        'refresh_token': refresh_token})
    else:
        return "Unauthorized", 401


@app.route('/', methods=['GET'])
@jwt_required
def index():
    res = col_users.find({})
    return json_util.dumps(list(res)), 200


@app.route('/refresh_token', methods=['GET'])
@jwt_refresh_required
def refresh_token():    
    token = col_tokens.find_one({'value': g.token})
    if token:
        col_tokens.delete_one({'value': g.token})
        token_payload = {'username': g.parsed_token['username']}
        access_token = create_access_token(token_payload)
        refresh_token = create_refresh_token(token_payload)
        col_tokens.insert_one({'value': refresh_token})
        return json_util.dumps({'access_token': access_token, 
                                'refresh_token': refresh_token}), 200
    else:
        return "Unauthorized", 401


# rota para visualizar o conteudo do payload encriptado no token.
@app.route('/token', methods=['GET'])
@jwt_required
def token():    
    return json_util.dumps(g.parsed_token), 200


@app.route('/users', methods=['POST'])
def create_user():
    data = request.get_json()
    data['password'] = generate_password_hash(data['password'])
    col_users.insert_one(data)
    return 'usuario ' + data['username'] + ' criado.', 201

@app.route('/users/<username>', methods=['GET'])
def get_user(username):
    return username, 200

# rota para exemplificar como utilizar obter variaveis
# de url. teste acessando 
# http://localhost:8088/questions/search?disciplina=1 
@app.route('/questions/search', methods=['GET'])
def search():
    disciplina = request.args.get('disciplina')
    return disciplina, 200

##Atividade - 00
@app.route('/v1/users', methods=['POST'])
def create_user_v1():
    data = request.get_json()
    data['password'] = generate_password_hash(data['password'])
    usuario_encontrado = col_users.find_one({'username' : data['username']})
    if not usuario_encontrado:
        col_users.insert_one(data)
        return 'usuario ' + data['username'] + ' criado.', 201
    else : 
        return 'usuario '+ data['username'] + ' já existente.', 203

##Atividade - 01 
@app.route('/v1/users/<username>', methods=['GET'])
def get_user_v1(username):
    usuario_encontrado = col_users.find_one({'username' : username})
    if usuario_encontrado:
        return json_util.dumps(usuario_encontrado), 200
    else : 
        return 'usuario '+ username + ' não encontrado', 404

##Atividade - 02
@app.route('/v1/authenticate', methods=['POST'])
def authenticate_user_v1():
    data = request.get_json()
    if not request or 'username' not in data or 'password' not in data:
        return 'dados não informados', 401
    else:
        usuario_encontrado = col_users.find_one({"username" : data['username'] }, {"_id" : 0,"password" : 1})
        for key, value in usuario_encontrado.items():
            password = value
        if not usuario_encontrado or not check_password_hash(password, data['password']):            
            return 'usuario ' + data['username'] + ' e/ou senha não encontrado.', 403
        else : 
            return 'usuario e senha válidos.', 200

##Atividade - 03
@app.route('/v1/users/update', methods=['POST'])
def update_user_v1():
    data = request.get_json()
    username = request.args.get('username')
    print(username)

    return 'teste', 200
    if not request or 'username' not in data or 'password' not in data:
        return 'dados não informados', 401
    else:
        print(data['password'])
        usuario_encontrado = col_users.find_one({"username" : data['username'] }, {"_id" : 0,"password" : 1})
        print(json_util.dumps(usuario_encontrado))
        for key, value in usuario_encontrado.items():
            password = value
        if not usuario_encontrado or not check_password_hash(password, data['password']):            
            return 'usuario ' + data['username'] + ' e/ou senha não encontrado.', 403
        else : 
            return 'usuario e senha válidos.', 200

