import logging
import random
import re
import time
from logging.handlers import RotatingFileHandler
from threading import Thread

from config import config, RET
from db_models import User, db, VerifyCode, LabeledDataUnit, LabeledSentence
from flask import Flask, request, current_app
from flask import session, jsonify
from flask_cors import CORS, cross_origin
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash
import requests

import jieba

app = Flask(__name__)
app.config['CORS_HEADERS'] = 'Content-Type'
CORS(app)  # cors 跨域处理 允许这个地址端口访问

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

app.config['MAIL_SERVER'] = 'smtp.qq.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USERNAME'] = '653082298@qq.com'
app.config['MAIL_PASSWORD'] = 'qffostofvizxbegj'
app.config["MAIL_DEFAULT_SENDER"] = '653082298@qq.com'

mail = Mail(app)

separators = {'。', '！', '!', '；', '？', '?'}


@app.after_request
def after_request(response):
    """设置默认的响应报文格式为application/json"""
    # 如果响应报文response的Content-Type是以text开头，则将其改为默认的json类型
    if response.headers.get("Content-Type").startswith("text"):
        response.headers["Content-Type"] = "application/json"
    return response


@app.route('/register', methods=['POST'])
def register():
    user_data = request.get_json()
    # 判断获取结果
    if not user_data:
        return jsonify(errno=RET.PARAMERR, errmsg='参数错误')
    name = user_data.get('name')
    title = user_data.get('title')
    organization = user_data.get('organization')
    email = user_data.get('email')
    password = user_data.get('password')
    if not re.match(r"^[A-Za-z0-9\u4e00-\u9fa5]+@[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)+$", email):
        return jsonify(errno=RET.PARAMERR, errmsg="邮箱格式不正确")

    # 检查参数的完整性
    if not all([name, title, organization, email, password]):
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
    user.name = name
    user.title = title
    user.organization = organization
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
    return jsonify(errno=RET.OK, errmsg='OK', data=user.to_dict())  # 登录成功，重定向到登录页


@app.route('/login', methods=['POST'])
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


@app.route('/captcha', methods=['POST'])  # 重置密码
def send_captcha():
    "qffostofvizxbegj"
    ss = "zxcvbnmsdfghjklqwertyuiop1234567890QWERTYUIOPKLJHGFDSAZXCVBNM"
    cc = ""  # 验证码
    for i in range(6):
        cc += random.choice(ss)
    msg = Message(subject="重置密码验证码",
                  recipients="")  # 一会修改
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
        return jsonify(errno=RET.NODATA, errmsg='用户名不存在')
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
        code = VerifyCode.query.filter_by(name=code_name).first()
    except Exception as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg='查询数据库错误')
    if code is not None:
        # 验证码已经存在，更新
        try:
            VerifyCode.query.filter_by(name=code_name).update({'value': cc})
            db.session.commit()
        except Exception as e:
            current_app.logger.error(e)
            # 写入数据如果发生异常需要进行回滚
            db.session.rollback()
            return jsonify(errno=RET.DBERR, errmsg='保存验证码异常')
    else:
        code = VerifyCode()
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
    return jsonify(errno=RET.OK, errmsg='OK')


def send_async_email(flask_app, msg):
    with flask_app.app_context():
        mail.send(msg)


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
        code = VerifyCode.query.filter_by(name='Verify_Code_' + email).first()
    except Exception as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg='查询数据库错误')
    if not user:
        return jsonify(errno=RET.NODATA, errmsg='用户名不存在')
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
        User.query.filter_by(email=email).update({'password_hash': generate_password_hash(password)})
        db.session.delete(code)
        db.session.commit()
    except Exception as e:
        current_app.logger.error(e)
        db.session.rollback()
        return jsonify(errno=RET.DBERR, errmsg='保存用户信息异常')
    session['user_id'] = user.id
    session['email'] = email
    return jsonify(errno=RET.OK, errmsg='OK', data=user.to_dict())


@app.route('/find-unit', methods=['POST'])
def find_unit():
    """接收语句，判断单位"""
    request_json = request.get_json()
    if not request_json:
        return jsonify(errno=RET.PARAMERR, errmsg="参数错误")

    email = request_json['email']
    try:
        user = User.query.filter_by(email=email).first()
    except Exception as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg='查询用户信息失败')

    original_text = request_json.get('original_text')
    if type(original_text) is not str:
        return jsonify(errno=RET.PARAMERR, errmsg="参数错误")

    selected_model = request_json.get('model').lower()
    # TODO: 加入ELMo选项
    if selected_model not in ['vanilla', 'bert']:
        return jsonify(errno=RET.PARAMERR, errmsg="参数错误")

    tokens, tags = get_unit_predictions(original_text, selected_model)

    return jsonify(errno=RET.OK, errmsg='OK', data={'tokens': tokens, 'tags': tags})


# TODO: 根据客户端请求调用相应模型
def get_unit_predictions(original_text, model):
    url_1 = ''
    url_2 = 'http://172.18.34.25:9000/api/find-units'
    json_data = {
        "text": original_text
    }
    if model == 'vanilla':
        r = requests.post(url_1, json=json_data)
    else:
        r = requests.post(url_2, json=json_data)
    data = r.json()
    tokens = []
    tags = []
    table = data['table']
    for seq in table:
        for tup in seq:
            tokens.append(tup[0])
            tags.append(0) if tup[1] == 'O' else tags.append(1)
    return tokens, tags


@app.route('/spelling-check', methods=['POST'])
def spelling_check():
    """接收语句，判断单位"""
    request_json = request.get_json()
    if not request_json:
        return jsonify(errno=RET.PARAMERR, errmsg="参数错误")

    email = request_json['email']
    try:
        user = User.query.filter_by(email=email).first()
    except Exception as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg='查询用户信息失败')

    text = request_json.get('text')
    if type(text) is not str:
        return jsonify(errno=RET.PARAMERR, errmsg="参数错误")

    json_data = {
        "text": text
    }

    url = "172.18.34.25:9001/api/spelling-check"
    r = requests.post(url, json=json_data)

    return r


@app.route('/submit-edit/unit', methods=['POST'])
def submit_edit():
    """提交新标注的数据"""
    request_json = request.get_json()
    if not request_json:
        return jsonify(errno=RET.PARAMERR, errmsg="参数错误")

    email = request_json.get('email')
    text = request_json.get('text')

    if not all([email, text]):
        return jsonify(errno=RET.PARAMERR, errmsg="参数不完整")

    try:
        user = User.query.filter_by(email=email).first()
    except Exception as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg='查询用户信息失败')

    if not user:
        return jsonify(errno=RET.NODATA, errmsg='用户名不存在')

    positions = request_json.get('positions')  # expected to be list of tuples: [(x1, x2), ...]
    chars = list(text)
    if positions:
        labels_c = create_iob_char(text, positions)
        words, labels_w = create_iob_word(text, positions)
    else:
        labels_c = ['O'] * len(text)
        words = list(jieba.cut(text))
        labels_w = ['O'] * len(words)

    list_of_chars, list_of_labels_c = separate_paragraph(chars, labels_c)
    list_of_words, list_of_labels_w = separate_paragraph(words, labels_w)

    for i in range(len(list_of_labels_c)):
        _text = ''.join(list_of_chars[i])
        labeled_data = LabeledDataUnit()
        labeled_data.creator = email
        labeled_data.original_text = _text
        labeled_data.chars = ' '.join(list_of_chars[i])
        labeled_data.iob_char = ' '.join(list_of_labels_c[i])
        labeled_data.words = ' '.join(list_of_words[i])
        labeled_data.iob_word = ' '.join(list_of_labels_w[i])
        try:
            db.session.add(labeled_data)
            db.session.commit()
        except Exception as e:
            current_app.logger.error(e)
            db.session.rollback()
            return jsonify(errno=RET.DBERR, errmsg='保存标注信息失败')

    return jsonify(errno=RET.OK, errmsg='OK')

@app.route('/submit-edit/spelling', methods=['POST'])
def submit_spelling():
    """提交修改数据（错别字）"""
    request_json = request.get_json()
    if not request_json:
        return jsonify(errno=RET.PARAMERR, errmsg="参数错误")

    email = request_json.get('email')
    text = request_json.get('text')

    if not all([email, text]):
        return jsonify(errno=RET.PARAMERR, errmsg="参数不完整")
    try:
        user = User.query.filter_by(email=email).first()
    except Exception as e:
        current_app.logger.error(e)
        return jsonify(errno=RET.DBERR, errmsg='查询用户信息失败')

    if not user:
        return jsonify(errno=RET.NODATA, errmsg='用户名不存在')

    positions = request_json.get('positions')
    list_of_sentences, list_of_labels = seperate_sentence(text, positions)
    for i in range(len(list_of_sentences)):
        labeled_sentence = LabeledSentence()
        labeled_sentence.creator = email
        labeled_sentence.text = list_of_sentences[i]
        labeled_sentence.labels = list_of_labels[i]
        try:
            db.session.add(labeled_sentence)
            db.session.commit()
        except Exception as e:
            current_app.logger.error(e)
            db.session.rollback()
            return jsonify(errno=RET.DBERR, errmsg='保存标注信息失败')

    return jsonify(errno=RET.OK, errmsg='OK')




def separate_paragraph(tokens, labels):
    list_of_tokens = []
    list_of_labels = []
    _tokens = []
    _labels = []
    for i in range(len(tokens)):
        if tokens[i] in separators:
            _labels.append(labels[i])
            _tokens.append(tokens[i])
            list_of_labels.append(_labels)
            list_of_tokens.append(_tokens)
            _labels = []
            _tokens = []
        else:
            _labels.append(labels[i])
            _tokens.append(tokens[i])
    if _tokens:
        list_of_tokens.append(_tokens)
    if _labels:
        list_of_labels.append(_labels)
    return list_of_tokens, list_of_labels

def seperate_sentence(text, positions):
    if positions is None:
        positions = []
    list_of_sentences = text.split('。')[0 : -1]
    list_of_lables = []
    length = 0
    position = 0

    for i in range(len(list_of_sentences)):
        list_of_sentences[i] += u'。'
        label = ""
        for j in range(len(list_of_sentences[i])):
            if position < len(positions) and positions[position] == length + j:
                label += 'B-Err,'
                position += 1
            else:
                label += 'O,'
        length += len(list_of_sentences[i])
        list_of_lables.append(label[0:-1])

    return list_of_sentences, list_of_lables




def create_iob_char(text, positions):
    labels = ['O'] * len(text)
    for tup in positions:
        start = tup[0]
        end = tup[1]  # TODO: NEED TO MAKE SURE IF 'end' SHOULD BE INCLUDED OR NOT
        for i in range(start, end + 1):
            if i == start:
                labels[i] = 'B-UNIT'
            else:
                labels[i] = 'I-UNIT'
    return labels


def create_iob_word(text, positions):
    tup = positions.pop(0)
    start = tup[0]
    end = tup[1]  # TODO: NEED TO MAKE SURE IF 'end' SHOULD BE INCLUDED OR NOT
    tokens = []
    labels = []
    # 临时字串变量
    other = ''
    unit = ''
    for i in range(len(text)):
        if i == start and i != end:  # 单位实体超过一个字符
            # 如果非单位实体临时字串非空，在结果中加入非单位实体标签
            if other:
                _tokens = list(jieba.cut(other))
                tokens.extend(_tokens)
                labels.extend(['O']*len(_tokens))
                # 清空临时字串变量
                other = ''
            unit += text[i]
        elif start < i < end:  # 单位实体超过两个字符
            unit += text[i]
        elif i != start and i == end:
            unit += text[i]
            _tokens = list(jieba.cut(unit))
            tokens.extend(_tokens)
            for j in range(len(_tokens)):
                if j == 0:
                    labels.append('B-UNIT')
                else:
                    labels.append('I-UNIT')
            # 重置起始位置
            if positions:
                tup = positions.pop(0)
                start = tup[0]
                end = tup[1]
            # 清空临时字串变量
            unit = ''
        elif i == start and i == end:  # 单位实体为单字符
            # 如果非单位实体临时字串非空，在结果中加入非单位实体标签
            if other:
                _tokens = list(jieba.cut(other))
                tokens.extend(_tokens)
                labels.extend(['O']*len(_tokens))
                # 清空临时字串变量
                other = ''
            tokens.append(text[i])
            labels.append('B-UNIT')
            # 重置起始位置
            if positions:
                tup = positions.pop(0)
                start = tup[0]
                end = tup[1]
        else:
            other += text[i]

    # 检查是否遗漏非单位实体字串
    if other:
        _tokens = list(jieba.cut(other))
        tokens.extend(_tokens)
        labels.extend(['O']*len(_tokens))

    return tokens, labels


@app.route("/")
def hello():
    return "<h1 style='color:blue'>智能审校线上评测系统终端</h1>"


# HTTP Errors handlers
@app.errorhandler(404)
def url_error(e):
    return """
    Wrong URL!
    <pre>{}</pre>""".format(e), 404


@app.errorhandler(500)
def server_error(e):
    return """
    An internal error occurred: <pre>{}</pre>
    See logs for full stacktrace.
    """.format(e), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
