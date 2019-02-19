# coding=utf-8

from datetime import datetime
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import pymysql
from config import Config

pymysql.install_as_MySQLdb()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = Config.SQLALCHEMY_DATABASE_URI

db = SQLAlchemy(app)
migrate = Migrate(app, db)


class BaseModel(object):
    """模型基类，提供时间"""
    create_time = db.Column(db.DateTime, default=datetime.now)
    update_time = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)


class User(BaseModel, db.Model):
    """用户"""
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)  # 用户编号
    name = db.Column(db.String(32), unique=True, nullable=True)  # 姓名
    title = db.Column(db.String(32), unique=True, nullable=True)  # 职务
    organization = db.Column(db.String(32), unique=True, nullable=True)  # 单位
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(40), unique=True, nullable=False)  # 邮箱

    @property
    def password(self):
        """获取密码时被调用"""
        raise AttributeError("不可读")

    @password.setter
    def password(self, passwd):
        self.password_hash = generate_password_hash(passwd)

    def check_password(self, passwd):
        return check_password_hash(self.password_hash, passwd)

    def to_dict(self):
        user_dict = {
            "user_id": self.id,
            "email": self.email,
            "name": self.name,
            "title": self.title,
            "organization": self.organization,
            "create_time": self.create_time.strftime("%Y-%m-%d %H:%M:%S")
        }
        return user_dict


class VerifyCode(BaseModel, db.Model):
    """保存验证码"""
    __tablename__ = 'verify_code'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    time = db.Column(db.String(50), nullable=False)
    value = db.Column(db.String(10), nullable=False)


class LabeledDataUnit(BaseModel, db.Model):
    """标注数据"""
    __tablename__ = "labeled_data_unit"
    id = db.Column(db.Integer, primary_key=True)
    creator = db.Column(db.String(40), nullable=False)
    original_text = db.Column(db.String(512), nullable=False)
    chars = db.Column(db.String(1024), nullable=False)
    iob_char = db.Column(db.String(1024), nullable=False)
    words = db.Column(db.String(1024), nullable=False)
    iob_word = db.Column(db.String(1024), nullable=False)
