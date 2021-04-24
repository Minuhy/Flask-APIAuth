Flask-APIAuth
==============

提供最基础的API登录认证功能

安装
------------
（还不会上传到pip）下载文件，复制到程序目录好了……

# 基本示例
----------------------------
```python
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
```
可以使用ApiPost或者PostMan测试接口。
首先要登录，参数写在Query里，有username和password两个
【POST】http://127.0.0.1:5000/api/login?username=john&password=hello
然后使用返回的token，参数写在Header里，名称为token，值为上一个请求返回的值
【GET】http://127.0.0.1:5000
成功得到用户信息。
退出登录即客户端删除token。

其他
---------

- [清风来叙 - 博客园 (cnblogs.com)](https://www.cnblogs.com/minuy)




----
Flask-APIAuth
==============

Provides the most basic API login authentication function

Install
------------
Download the file and copy it to the program directory

# Examples
----------------------------
```python
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
                    'message': 'login success'  
  }  
        else:  
            return {  
                    'code': '403',  
                    'data': {},  
                    'message': 'login error'  
  }  
    else:  
        return {  
                'code': '403',  
                'data': {},  
                'message': 'parameters error'  
  }  
  
  
@auth.error_content  
def error_content():  
    return {  
        'code': '403',  
        'data': {},  
        'message': 'please login'  
  }  
  
  
@auth.verify_password  
def verify_password(username, password):  
    if username in users and users.get(username) == password:  
        print('password ok')  
        # 返回的数据是下面auth.current_user拿到的  
  return {'username': username, 'sex': 'man'}  
  
  
@app.route('/')  
@auth.login_required  
def index():  
    return {  
        'code': '200',  
        'data': {  
            'name': auth.current_user.get('username'),  
            'sex': auth.current_user.get('sex')  
        },  
        'message': 'success'  
  }  
  
  
if __name__ == '__main__':  
    app.run()
```
You can use apipost or postman to test the interface.
First of all, you need to log in. The parameters are written in query. There are two parameters: username and password
【POST】http://127.0.0.1:5000/api/login?username=john&password=hello
Then the returned token is used, and the parameters are written in the header. The name is token and the value is the value returned by the previous request
【GET】http://127.0.0.1:5000
Get the user information successfully.
Log out means that the client will delete the token.

Other
---------

- [blog (cnblogs.com)](https://www.cnblogs.com/minuy)
