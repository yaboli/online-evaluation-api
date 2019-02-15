import sys
import logging
from flask import Flask, request, current_app
from sql_manager import SQLManager
import datetime
from flask_sqlalchemy import SQLAlchemy

from config import config,Config, RET
from logging.handlers import RotatingFileHandler
import functools
from flask import g, session, jsonify

import re
import random
from flask_mail import Mail, Message
from threading import Thread
from werkzeug.security import generate_password_hash
import json
from db_models import User, TagInfo, db, Verify_code
import time
from flask_cors import CORS, cross_origin


app = Flask(__name__)
app.config['CORS_HEADERS'] = 'Content-Type'
CORS(app, resources={r"/unit/*": {"origins": "http://172.18.34.56:8081"}})  # cors 跨域处理 允许这个地址端口访问
# db = SQLAlchemy()

# 设置日志记录等级
logging.basicConfig(level=logging.ERROR)  # 调试debug级
file_log_handler = RotatingFileHandler('logs/log', maxBytes=1024 * 1024 * 100, backupCount=10)
formatter = logging.Formatter('%(levelname)s %(filename)s:%(lineno)d %(message)s')
# 为刚创建的日志记录器设置日志记录格式
file_log_handler.setFormatter(formatter)
# 为全局的日志工具对象（应用程序实例app使用的）添加日后记录器
logging.getLogger().addHandler(file_log_handler)
app.config.from_object(config['development'])
# 数据库处理
db.init_app(app)

# 全域变量，负责用户信息与标注数据管理
sql_manager = SQLManager()


def build_sql_dict(user_id, text):
    return {"user_id": user_id,
            "time": datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'),
            "text": text}


# 插入新标注的数据
@app.route("/insert-new-data", methods=['POST'])
def insert_new_data():

    request_json = request.json
    user_id = request_json["user_id"]
    text = request_json["text"]

    # TODO: 获取并解析标签

    dic = build_sql_dict(user_id, text)
    mark = sql_manager.insert_new_data(dic)

    if mark == 1:
        return "Data inserted successfully", 200
    else:
        return "An error occurred during data insertion", 500


app.config['MAIL_SERVER'] = 'smtp.qq.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USERNAME'] = '653082298@qq.com'
app.config['MAIL_PASSWORD'] = 'qffostofvizxbegj'
app.config["MAIL_DEFAULT_SENDER"] = '653082298@qq.com'

mail = Mail(app)


@app.after_request
@cross_origin(origin='172.18.34.56:8081', headers=['Content-Type']) #cors 跨域处理 允许这个地址端口访问
def after_request(response):
    """设置默认的响应报文格式为application/json"""
    # 如果响应报文response的Content-Type是以text开头，则将其改为默认的json类型
    if response.headers.get("Content-Type").startswith("text"):
        response.headers["Content-Type"] = "application/json"
    return response


@app.route('/unit/register', methods=['POST'])
@cross_origin(origin='172.18.34.56:8081', headers=['Content-Type']) #cors 跨域处理 允许这个地址端口访问
def register():

    user_data = request.get_json()
    print(user_data)
    # 判断获取结果
    if not user_data:
        return jsonify(errno=RET.PARAMERR, errmsg='参数错误')
    email = user_data.get('email')
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
            return jsonify(errno=RET.DATAEXIST, errmsg='邮箱号已注册')
    user = User()
    user.email = email
    user.password = password
    try:
        db.session.add(user)
        db.session.commit()
    except Exception as e:
        current_app.logger.error(e)
        # 如果提交数据发生异常,需要进行回滚
        db.session.rollback()
        return jsonify(errno=RET.DBERR, errmsg='保存用户信息失败')
    return jsonify(errno=RET.OK, errmsg='OK', data=user.to_dict())   # 登录成功，重定向到登录页


@app.route('/unit/login', methods=['POST'])
@cross_origin(origin='172.18.34.56:8081', headers=['Content-Type'])  # cors 跨域处理 允许这个地址端口访问
def login():
    user_data = request.get_json()
    if not user_data:
        return jsonify(errno=RET.PARAMERR, errmsg='参数错误')
    email = user_data.get('email')
    password = user_data.get('password')
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
    return jsonify(errno=RET.OK, errmsg='OK', data=user.to_dict())


@app.route('/unit/captcha', methods=['POST'])     # 重置密码
@cross_origin(origin='172.18.34.56:8081', headers=['Content-Type'])  #cors 跨域处理 允许这个地址端口访问
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
    msg.recipients = [user_name]
    try:
        thread = Thread(target=send_async_email, args=[app, msg])
        thread.start()
    except Exception as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg='邮件发送失败')
    code_name = 'Verify_Code_' + user_name
    # 如果重复发送，更新
    try:
        code = Verify_code.query.filter_by(name=code_name).first()
    except Exception as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg='查询数据库错误')
    if code is not None:
        # 验证码已经存在，更新
        try:
            Verify_code.query.filter_by(name=code_name).update({'value': cc})
            db.session.commit()
        except Exception as e:
            current_app.logger.error(e)
            # 写入数据如果发生异常需要进行回滚
            db.session.rollback()
            return jsonify(errno=RET.DBERR, errmsg='保存验证码异常')
    else:
        code = Verify_code()
        ti = time.time()
        code.time = ti
        code.name = 'Verify_Code_' + user_name
        code.value = cc
        try:
            db.session.add(code)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(e)
            return jsonify(errno=RET.DBERR, errmsg='查询数据库错误')
    return jsonify(errno=RET.OK,errmsg='OK')


@app.route('/unit/changepass', methods=['POST'])
@cross_origin(origin='172.18.34.56:8081', headers=['Content-Type'])  # cors 跨域处理 允许这个地址端口访问
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
        code = Verify_code.query.filter_by(name='Verify_Code_' + email).first()
    except Exception as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg='查询数据库错误')
    if not user:
        return jsonify(errno=RET.NODATA,errmsg='用户名不存在')
    # 校验验证码
    if not code:
        return jsonify(errno=RET.NODATA, errmsg='验证码错误')
    ctime = code.time
    now = time.time()
    if float(now) - float(ctime) > 300:
        try:
            db.session.delete(code)
            db.session.commit()
        except:
            pass
        return jsonify(errno=RET.NODATA, errmsg='验证码过期')
    if verify_code.lower() != code.value.lower():
        return jsonify(errno=RET.DATAERR, errmsg='验证码错误')
    # 删除验证码,验证码只能操作一次
    try:
        User.query.filter_by(email=email).update({'password_hash':generate_password_hash(password)})
        db.session.delete(code)
        db.session.commit()
    except Exception as e:
        current_app.logger.error(e)
        db.session.rollback()
        return jsonify(errno=RET.DBERR,errmsg='保存用户信息异常')
    session['user_id'] = user.id
    session['email'] = email
    return jsonify(errno=RET.OK, errmsg='OK', data=user.to_dict())


@app.route('/unit/findunit', methods=['POST'])
@cross_origin(origin='172.18.34.56:8081', headers=['Content-Type']) #cors 跨域处理 允许这个地址端口访问
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
@cross_origin(origin='172.18.34.56:8081', headers=['Content-Type']) #cors 跨域处理 允许这个地址端口访问
def commit_error():
    """提交标注错误"""
    data = request.get_json()
    if not data:
        return jsonify(errno=RET.PARAMERR, errmsg="参数错误")
    email = data.get('email')
    sentence = data.get('message')
    tags = data.get('tags')
    if not all([sentence, tags, email]):
        return jsonify(errno=RET.PARAMERR, errmsg="参数不完整")
    try:
        user = User.query.filter_by(email=email).first()
    except Exception as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg='查询用户信息失败')
    if not user:
        return jsonify(errno=RET.NODATA, errmsg='用户名不存在')
    info = TagInfo()
    info.sentence = str(sentence)
    info.tags = str(tags)
    info.submitter = email
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


@app.route("/")
@cross_origin(origin='172.18.34.56:8081', headers=['Content-Type'])  #cors 跨域处理 允许这个地址端口访问
def hello():
    version = "{}.{}".format(sys.version_info.major, sys.version_info.minor)
    message = "Hello World from Flask in a uWSGI Nginx Docker container with Python {} (default)".format(
        version
    )
    return message


# HTTP Errors handlers
@app.errorhandler(404)
@cross_origin(origin='172.18.34.56:8081', headers=['Content-Type'])  #cors 跨域处理 允许这个地址端口访问
def url_error(e):
    return """
    Wrong URL!
    <pre>{}</pre>""".format(e), 404


@app.errorhandler(500)
@cross_origin(origin='172.18.34.56:8081', headers=['Content-Type'])  #cors 跨域处理 允许这个地址端口访问
def server_error(e):
    return """
    An internal error occurred: <pre>{}</pre>
    See logs for full stacktrace.
    """.format(e), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True, port=8801)
