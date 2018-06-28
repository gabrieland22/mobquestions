from flask import Flask, request, jsonify, redirect, g
from flask_pymongo import PyMongo

from werkzeug.security import generate_password_hash, check_password_hash

from bson import json_util

from config import MONGO_URI, MONGO_URI_TESTS, REDIS_HOST, REDIS_PORT, REDIS_PASSWORD
from auth import *

import os
import redis

rcache = redis.Redis(
            host=REDIS_HOST, 
            port=REDIS_PORT,
            password=REDIS_PASSWORD)


def create_app(testing = False):
    app = Flask(__name__)
    if os.getenv('FLASK_TESTING') and os.getenv('FLASK_TESTING')=='1':
        app.config['MONGO_URI'] = MONGO_URI_TESTS
    else:
        app.config['MONGO_URI'] = MONGO_URI
    app.config['PRESERVE_CONTEXT_ON_EXCEPTION'] = False
    app_context = app.app_context()
    app_context.push()        
    return app

mongo = None
app = create_app()
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

@app.route('/cached_example', methods=['GET'])
def questao_mais_legal_cacheada():    
    if rcache and rcache.get('questao_legal'):
        return rcache.get('questao_legal'), 200
    else:
        question = col_questions.find({'id': 'c14ca8e5-b7'})
        if rcache:
            rcache.set('questao_legal', json_util.dumps(question))
    return json_util.dumps(question), 200

@app.route('/not_cached_example', methods=['GET'])
def questao_mais_legal():    
    question = col_questions.find({'id': 'bc3b3701-b7'})
    return json_util.dumps(question), 200


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
    if 'password' not in data.keys() or 'username' not in data.keys():
        return 'Dados insuficientes.', 400
    data['password'] = generate_password_hash(data['password'])
    col_users.insert_one(data)
    del(data['password'])
    return json_util.dumps(data), 201


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

##Atividade - 04
@app.route('/v1/users/<username>', methods=['PATCH'])
def update_password_user_v1(username):
    data = request.get_json()
    data['password'] =  generate_password_hash(data['password'])
    usuario_encontrado = col_users.find_one({'username' : username})
    if not usuario_encontrado:
        return 'usuario '+ username + ' não encontrado', 404
    else:
        col_users.update({'username': username}, {'$set':{'password': data['password'] }})
        return 'senha atualizada.', 200
 
 ## Atividade - 05
@app.route('/v1/questions/<question_id>', methods=['GET'])
def get_question(question_id):
    questao_encontrada = col_questions.find_one({'id' : question_id})
    if questao_encontrada:
        return json_util.dumps(questao_encontrada), 200
    else : 
        return 'Questão '+ question_id + ' não foi encontrada.', 404

##Atividade - 06
@app.route('/v1/questions/<question_id>', methods=['POST'])
@jwt_required
def inserir_comentario_questao(question_id):
    data = request.get_json()
    print(col_questions.find_one())
    if not question_id or not request or 'username' not in data or 'message' not in data:
        return 'Dados não informados e/ou não encontrados para atualização', 401
    else:
        usuario_encontrado = col_users.find_one({"username" : data['username'] })
        questao_encontrada = col_questions.find_one({'id' : question_id})
        if not usuario_encontrado or not questao_encontrada:
            return 'Usuário e/ou questão não encontrados', 403
        else:
            col_questions.update({'id' : question_id}, {'$set': {'comentarios' : data}})
            return 'Comentário inserido com sucesso', 201

##Atividade - 07
@app.route('/v1/questions/search', methods=['GET'])
def get_questoes():
    disciplina = request.args.get('disciplina')
    ano = request.args.get('ano')

    if not disciplina and not ano:
        return 'Dados enviados estão inválidos', 400
    else:
        where = {}
        where['disciplina'] = int(disciplina)
        where['ano'] = int(ano)
        questions_encontradas = col_questions.find(where)
        if questions_encontradas:
            return json_util.dumps(list(questions_encontradas)), 200
        else:
            return 'Dados não encontrados', 404

##Atividade - 08
##Requerer token válido da atividade 03 e 06

##Atividade - 09
@app.route('/v1/questions/<question_id>/answer', methods=['POST'])
@jwt_required
def responder_questao(question_id):
    data = request.get_json()
    if not question_id or not request or 'resposta' not in data or 'username' not in data:
        return 'Dados não informados e/ou não encontrados', 401
    else:
        questao = col_questions.find_one({'id' : question_id})
        if not questao:
            return 'Questão não encontrada', 403
        else:
            usuario_encontrado = col_users.find_one({'username' : data['username']})
            if usuario_encontrado:
                answerUser = {}
                answerUser['id'] = question_id
                answerUser['answer'] = data['resposta']
                if 'questoes' not in usuario_encontrado:
                    col_users.update({'username' : data['username']}, {'$set': {'questoes' : [answerUser]}})
                else:
                    col_users.update({'username' : data['username']}, {'$push': {'questoes' : answerUser}})

                questoes_encontradas = col_users.find({'questoes': {'$ne' : None} },{'_id':0,'questoes.id' : 1})
                lista = []
                contador = int(0)
                if questoes_encontradas:
                    for x in questoes_encontradas:
                        if len(x) > 0:     
                            for i in x['questoes']:
                                if i['id'] == question_id:
                                    contador = contador + 1
                col_questions.update({'id' : question_id}, {'$set': {'contador_respostas_recebida' : contador}})


                if questao['resposta'] == data['resposta']:
                    return 'Resposta correta', 201
                else:
                    return 'Resposta incorreta', 201
            else: 
                return 'Usuário não encontrado', 403

##Atividade - 10
@app.route('/v1/questions/answers', methods=['GET'])
@jwt_required
def get_respostas_questoes():
    questoes_encontradas = col_users.find({'questoes': {'$ne' : None} },{'_id':0,'questoes' : 1})
    
    lista = []
    if questoes_encontradas:
        for x in questoes_encontradas:
            if len(x) > 0:     
                for i in x['questoes']:
                    lista.append(i)
    if len(lista) == 0:
        return 'Nenhuma resposta encontrada', 404

    return json_util.dumps(list(lista)), 201

##Atividade - 11
@app.route('/v1/featured_questions', methods=['POST'])
@jwt_required
def questoes_mais_respondidas():
    questions = col_questions.find({'contador_respostas_recebida': {'$ne' : None}, 'contador_respostas_recebida' : {'$gt' : 0} })
    print(json_util.dumps(list(questions)))
    if questions and rcache:
        rcache.set('questao_mais_respondida', json_util.dumps(list(questions)))
        return 'Dados atualizados', 200
    return 'Dados não atualizados', 403

##Atividade - 12
@app.route('/v1/featured_questions', methods=['GET'])
@jwt_required
def get_questoes_mais_respondidas():
    if rcache and rcache.get('questao_mais_respondida'):
        return rcache.get('questao_mais_respondida'), 200
    return 'Não possui dados em cache',403








