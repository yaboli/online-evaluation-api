# coding=utf-8

from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager
from flask_sqlalchemy import SQLAlchemy
# from web_app import app,db
db = SQLAlchemy()
import pymysql
pymysql.install_as_MySQLdb()


class BaseModel(object):
    """模型基类，提供时间"""
    create_time = db.Column(db.DateTime, default=datetime.now)
    updata_time = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)


class User(BaseModel, db.Model):
    """用户"""
    __tablename__ = "user_profile"
    id = db.Column(db.Integer, primary_key=True)  # 用户编号
    name = db.Column(db.String(32), unique=True,nullable=True)    # 昵称
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
            "email":self.email,
            "name":self.name,
            "create_time":self.create_time.strftime("%Y-%m-%d %H:%M:%S")
        }
        return user_dict


class TagInfo(BaseModel, db.Model):
    """标注数据"""
    __tablename__="tag_data"
    id = db.Column(db.Integer, primary_key=True)
    submitter = db.Column(db.String(40), nullable=False)
    sentence = db.Column(db.String(1000), nullable=False)
    tags = db.Column(db.String(1000), nullable=False)


class Verify_code(BaseModel, db.Model):
    """保存验证码"""
    __tablename__ = 'verify_code'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    time = db.Column(db.String(50), nullable=False)
    value = db.Column(db.String(10), nullable=False)

# #
# Migrate(app=app, db=db)
# manager = Manager(app)
# manager.add_command("db", MigrateCommand)
# if __name__ == '__main__':
#     manager.run()
