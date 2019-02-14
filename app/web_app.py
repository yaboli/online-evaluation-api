# coding=utf-8
import logging
import redis
from flask import Blueprint, render_template, flash, redirect, url_for, request, current_app,Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_session import Session
from config import config,Config, RET
from logging.handlers import RotatingFileHandler
import functools
from flask import g, session, jsonify
from werkzeug.routing import BaseConverter
from db_models import User, TagInfo
import re
import random
from flask_mail import Mail, Message
from threading import Thread
from werkzeug.security import generate_password_hash
import json


class RegexConverter(BaseConverter):
    """在路由中使用正则表达式进行参数提取的转换工具"""
    def __init__(self, url_map, *args):
        super(RegexConverter, self).__init__(url_map)
        self.regex = args[0]


app = Flask(__name__)
# 创建数据库对象
db = SQLAlchemy()
# 创建redis对象
redis_store = redis.StrictRedis(host=Config.REDIS_HOST, port=Config.REDIS_PORT)
csrf = CSRFProtect()
# 设置日志记录等级
logging.basicConfig(level=logging.DEBUG)  # 调试debug级
file_log_handler = RotatingFileHandler('logs/log', maxBytes=1024 * 1024 * 100, backupCount=10)

formatter = logging.Formatter('%(levelname)s %(filename)s:%(lineno)d %(message)s')
# 为刚创建的日志记录器设置日志记录格式
file_log_handler.setFormatter(formatter)
# 为全局的日志工具对象（应用程序实例app使用的）添加日后记录器
logging.getLogger().addHandler(file_log_handler)
app.config.from_object(config['development'])
app.url_map.converters["regex"] = RegexConverter
# 数据库处理
db.init_app(app)
# csrf保护
csrf.init_app(app)
# 使用flask-session扩展，用redis保存redis
Session(app)
app.config['MAIL_SERVER'] = 'smtp.qq.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USERNAME'] = '653082298@qq.com'
app.config['MAIL_PASSWORD'] = 'qffostofvizxbegj'
app.config["MAIL_DEFAULT_SENDER"] =  '653082298@qq.com'

mail = Mail(app)


@app.after_request
def after_request(response):
    """设置默认的响应报文格式为application/json"""
    # 如果响应报文response的Content-Type是以text开头，则将其改为默认的json类型
    if response.headers.get("Content-Type").startswith("text"):
        response.headers["Content-Type"] = "application/json"
    return response


def login_required(f):
    """登录验证装饰器"""
    @functools.wraps(f)
    def wrapper(*args,**kwargs):
        user_id = session.get('user_id')
        if user_id is None:
            return jsonify(errno=RET.SESSIONERR, errmsg="用户未登录")
        else:
            g.user_id = user_id
            return f(*args, **kwargs)
    return wrapper


@app.route('/unit/register', methods=['POST'])
def register():
    # 获取参数
    user_data = request.get_json()
    # 判断获取结果
    if not user_data:
        return jsonify(errno=RET.PARAMERR, errmsg='参数错误')
    # 获取详细的参数信息,mobile,sms_code,password
    # user_data['mobile']
    email = user_data.get('email')
    # sms_code = user_data.get('sms_code')
    password = user_data.get('password')
    if not re.match(r"^[A-Za-z0-9\u4e00-\u9fa5]+@[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)+$", email):
        return jsonify(errno=RET.PARAMERR, errmsg="邮箱格式不正确")

    # 检查参数的完整性
    if not all([email, password]):
        return jsonify(errno=RET.PARAMERR, errmsg='参数缺失')
    # 判断用户是否已经注册
    try:
        user = User.query.filter_by(email=email).first()
    except Exception as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg='查询数据库异常')
    else:
        # 判断查询结果
        if user:
            return jsonify(errno=RET.DATAEXIST, errmsg='手机号已注册')
    user = User()
    user.email = email
    # 调用模型类中的方法generate_password_hash,对密码进行加密sha256处理
    user.password = password
    # 提交数据到数据库
    try:
        db.session.add(user)
        db.session.commit()
    except Exception as e:
        current_app.logger.error(e)
        # 如果提交数据发生异常,需要进行回滚
        db.session.rollback()
        return jsonify(errno=RET.DBERR, errmsg='保存用户信息失败')
    # 缓存用户信息
    # session['user_id'] = user.id
    # session['email'] = email
    # session['name'] = mobile
    # 返回结果
    return jsonify(errno=RET.OK, errmsg='OK', data=user.to_dict())   # 登录成功，重定向到登录页


@app.route('/unit/login', methods=['POST'])
def login():
    # if request.method == 'GET':
    #     return render_template('templates/login.html')
        # 获取参数post请求
    user_data = request.get_json()
    # 校验参数的存在
    if not user_data:
        return jsonify(errno=RET.PARAMERR, errmsg='参数错误')
    # 获取详细的参数信息,mobile,password
    email = user_data.get('email')
    password = user_data.get('password')
    # 检查参数的完整性
    if not all([email, password]):
        return jsonify(errno=RET.PARAMERR, errmsg='参数不完整')
    # 校验邮箱格式
    if not re.match(r"^[A-Za-z0-9\u4e00-\u9fa5]+@[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)+$", email):
        return jsonify(errno=RET.PARAMERR, errmsg="邮箱格式不正确")
    # 查询数据库,确认用户的存在,保存查询结果
    try:
        user = User.query.filter_by(email=email).first()
    except Exception as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg='查询数据库异常')
    # 校验查询结果,确认用户已注册/确认密码正确
    if user is None or not user.check_password(password):
        return jsonify(errno=RET.DATAERR, errmsg='用户名或密码错误')
    # 缓存用户信息
    """
    如果要实现状态保持:
    def login_required():
        user_id = session.get('user_id')
        if user_id:
            g.user_id = user_id
        else:
            return jsonify(errno=RET.SESSIONERR,errmsg='用户未登陆')

    """
    session['user_id'] = user.id
    session['email'] = user.email
    # 如果用户修改了用户名信息,不能指定用户名为手机号
    # session['name'] = user.name
    # 返回结果
    return jsonify(errno=RET.OK, errmsg='OK', data=user.to_dict())


@app.route('/unit/captcha', methods=['POST'])     # 重置密码
def send_captcha():
    "qffostofvizxbegj"
    ss = "zxcvbnmsdfghjklqwertyuiop1234567890QWERTYUIOPKLJHGFDSAZXCVBNM"
    cc = ""   # 验证码
    for i in range(6):
        cc += random.choice(ss)
    msg = Message(subject="重置密码验证码",
                  recipients="")       # 一会修改
    msg.body = "重置密码验证码为：{}".format(cc)
    user_data = request.get_json()
    if not user_data:
        return jsonify(errno=RET.PARAMERR, errmsg='参数错误')
    user_name = user_data.get("email")
    try:
        user = User.query.filter_by(email=user_name).first()
    except Exception as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg='查询数据库错误')
    if not user:
        return jsonify(errno=RET.NODATA,errmsg='用户名不存在')
    try:
        thread = Thread(target=send_async_email, args=[app, msg])
        thread.start()
    except Exception as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg='邮件发送失败')
    try:
        redis_store.setex("Verify_Code_" + user_name, 300, cc)  # 将用户名写入redis
    except Exception as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg='查询数据库错误')

    return jsonify(errno=RET.OK,errmsg='OK')


@app.route('/changepass', methods=['POST'])
def change_password():
    user_data = request.get_json()
    if not user_data:
        return jsonify(errno=RET.PARAMERR, errmsg='参数错误')

    email = user_data.get('email')
    password = user_data.get('password')
    verify_code = user_data.get('verify_code')
    # 检查参数的完整性
    if not all([email, password, verify_code]):
        return jsonify(errno=RET.PARAMERR, errmsg='参数不完整')
    # 验证用户名存在
    try:
        user = User.query.filter_by(email=email).first()
    except Exception as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg='查询数据库错误')
    if not user:
        return jsonify(errno=RET.NODATA,errmsg='用户名不存在')
    # 校验验证码
    try:
        real_image_code = redis_store.get('Verify_Code_' + email)
    except Exception as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR,errmsg='查询验证码失败')
    if not real_image_code:
        return jsonify(errno=RET.NODATA, errmsg='验证码过期')
    # 删除图片验证码,图片验证码只能操作一次
    try:
        redis_store.delete('Verify_Code_' + email)
    except Exception as e:
        current_app.logger.error(e)
    # 比较图片验证码是否一致,忽略大小写
    if real_image_code.lower() != verify_code.lower():
        return jsonify(errno=RET.DATAERR, errmsg='验证码错误')
    try:
        User.query.filter_by(email=email).update({'password_hash':generate_password_hash(password)})
        db.session.commit()
    except Exception as e:
        current_app.logger.error(e)
        # 写入数据如果发生异常需要进行回滚
        db.session.rollback()
        return jsonify(errno=RET.DBERR,errmsg='保存用户信息异常')
    session['user_id'] = user.id
    session['email'] = email
    return jsonify(errno=RET.OK, errmsg='OK', data=user.to_dict())


@app.route('/unit/findunit', methods=['POST'])
@login_required
def find_unit():
    """接收语句，判断单位"""
    info = request.get_json()
    if not info:
        return jsonify(errno=RET.PARAMERR, errmsg="参数错误")
    message = info.get('message')
    if type(message) is not str:
        return jsonify(errno=RET.PARAMERR, errmsg="参数错误")
    # sentence, tag = seq_tagger.predict(message)
    # return jsonify(errno=RET.OK, errmsg='OK', data={'sentence': sentence, "tag": tag})


@app.route('/unit/commiterror', methods=['POST'])
@login_required
def commit_error():
    """提交标注错误"""
    user_id = g.user_id
    data = request.get_json()
    if not data:
        return jsonify(errno=RET.PARAMERR, errmsg="参数错误")
    sentence = data.get('message')
    tags = data.get('tags')
    if not all([sentence, tags]):
        return jsonify(errno=RET.PARAMERR, errmsg="参数错误")
    try:
        user = User.query.filter_by(id=user_id).first()
    except Exception as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg='查询用户信息失败')
    user_name = user.email
    info = TagInfo()
    info.sentence = str(sentence)
    info.tags = str(tags)
    info.submitter = user_name
    try:
        db.session.add(info)
        db.session.commit()
    except Exception as e:
        current_app.logger.error(e)
        db.session.rollback()
        return jsonify(errno=RET.DBERR, errmsg='保存标注信息失败')
    return jsonify(errno=RET.OK, errmsg='OK')


def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)


if __name__ == '__main__':
    print(app.url_map)
    app.run(debug=True, host='0.0.0.0', port=5001)


