"""
flask_apiauth
==================

此模块为flaks API登录提供基本的认证和简单token生成功能
This module provides basic authentication and simple token
 generation functions for the flaks API login

:copyright: (C) 2021 by Minuy.
:license: MIT, see LICENSE for more details.
"""

from functools import wraps
from flask import request, g
import base64

__version__ = '1.0.0dev'


class ApiAuth(object):
    def __init__(self, split_character=' '):
        # 分割词，最好唯一且不出现在账号里
        # Segmentation words, preferably 
        # unique and do not appear in the account
        self.split_character = split_character
        self.verify_password_callback = None
        self.error_content_callback = None

    def verify_password(self, f):
        """ 验证密码回调，此回调返回的非空数据将放在current_user中
        Verify the password callback, and the non empty data returned
        by this callback will be placed in current_ In user """
        # print('设置密码验证函数')
        self.verify_password_callback = f
        return f

    def error_content(self, f):
        """ 错误数据回调，此回调应返回登录、验证失败回复给客户端的内容 """
        # print('设置错误内容函数')
        self.error_content_callback = f
        return f

    def get_token(self, username=None, password=None):
        """ 根据账号和密码（hash）生成token，用于登录函数 
        Error data callback, which should return the content of 
        login and authentication failure reply to the client"""
        # print('生成token')
        token = username + self.split_character + password
        return base64.urlsafe_b64encode(token.encode("utf-8")).decode()

    def authentication_failed(self):
        """ 认证失败调用
        Authentication failed call """
        # print('验证密码失败')
        # 如果有错误内容处理，返回错误内容
        if self.error_content_callback:
            # print('返回自定义错误数据')
            return self.error_content_callback()
        else:
            # 否则返回文字，登录失败
            return 'login failed'

    @property
    def current_user(self):
        """ 登录后通过这个属性获取在verify_password函数里返回的内容（用户信息）
        After logging in, you can get the_ The content returned by the
        password function (user information) """
        if hasattr(g, 'flask_api_auth_user'):
            return g.flask_api_auth_user

    def login_required(self, f=None):
        """ 登录拦截，没有相应的请求头或者验证密码返回空值会返回错误信息 
        Login interception, no corresponding request header or verification password,
        return a null value will return an error message"""
        def login_required_internal(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                auth_user = None
                if 'token' in request.headers:
                    # print('token存在')
                    try:
                        # 把账号和密码hash都一起打包到base64里
                        # Package account and password hash into Base64
                        token = base64.urlsafe_b64decode(request.headers['token']).decode('utf-8')
                        # print('token：', token)
                        # 账号和密码hash之间使用空格分割
                        # Use space division between account and password hash
                        user, hash_password = token.split(self.split_character, 1)
                        # print('user：', user, 'hash_password', hash_password)
                        # 如果账号和密码都存在
                        if user and hash_password:
                            auth_user = {'user': user, 'pwd': hash_password}
                    except (ValueError, KeyError):
                        # 如果解析失败或者没有token
                        # print('token解析失败')
                        pass
                # 没提交参数
                else:
                    # 在这里可以特别设置未登录的提醒
                    return self.authentication_failed()

                # print('auth', auth_user)
                # 如果存在用户信息，开始验证密码
                if auth_user:
                    user = None
                    # 如果有密码验证函数
                    if self.verify_password_callback:
                        # print('开始验证密码')
                        user = self.verify_password_callback(auth_user.get('user'), auth_user.get('pwd'))
                        if user:
                            # print('密码验证成功')
                            # 如果user不为空，加载
                            g.flask_api_auth_user = user if user is not True \
                                else auth_user.get('user') if auth_user else None
                    # 如果user为空
                    if user in (False, None):
                        return self.authentication_failed()
                else:
                    # 用户信息不存在
                    # User information does not exist
                    return self.authentication_failed()

                return f(*args, **kwargs)
            return decorated

        if f:
            return login_required_internal(f)
        return login_required_internal
