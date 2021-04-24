# coding:utf-8
from flask import Flask, request
from werkzeug.security import generate_password_hash, check_password_hash

from flask_apiauth import ApiAuth

app = Flask(__name__)
auth = ApiAuth()

users = {
    "john": generate_password_hash("hello"),
    "susan": generate_password_hash("bye")
}


@app.route('/api/login', methods=['POST'])
def get_auth():
    username = request.args.get('username')
    print(username)
    password = request.args.get('password')
    print(password)
    if username and password:
        if username in users and check_password_hash(users.get(username), password):
            token = auth.get_token(username, users.get(username))
            return {
                    'code': '200',
                    'data': {
                        'token': token
                    },
                    'message': '登录成功'
                }
        else:
            return {
                    'code': '403',
                    'data': {},
                    'message': '账号或密码错误'
                }
    else:
        return {
                'code': '403',
                'data': {},
                'message': '参数不完整'
            }


@auth.error_content
def error_content():
    return {
        'code': '403',
        'data': {},
        'message': '请先登录'
    }


@auth.verify_password
def verify_password(username, password):
    if username in users and users.get(username) == password:
        print('密码正确')
        # 返回的数据是下面auth.current_user拿到的
        return {'username': username, 'sex': '男'}


@app.route('/')
@auth.login_required
def index():
    return {
        'code': '200',
        'data': {
            'name': auth.current_user.get('username'),
            'sex': auth.current_user.get('sex')
        },
        'message': '成功'
    }


if __name__ == '__main__':
    app.run()
