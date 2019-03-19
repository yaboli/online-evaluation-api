# coding=utf-8


class Config:
    """配置基本参数"""
    SECRET_KEY = "TQ6uZxn+SLqiLgVimX838/VplIsLbEP5jV7vvZ+Ohqw="

    # flask-sqlalchemy使用的参数
    # SQLALCHEMY_DATABASE_URI = "mysql://root:passwrd@192.168.99.100:3306/zhi_neng_shen_jiao"  # 本地数据库
    SQLALCHEMY_DATABASE_URI = "mysql://root:@172.18.34.25:3306/zhi_neng_shen_jiao?charset=utf8mb4"  # 服务器数据库
    SQLALCHEMY_TRACK_MODIFICATIONS = True  # 追踪数据库的修cond改行为，如果不设置会报警告，不影响代码的执行


class DevelopmentConfig(Config):
    """开发模式的配置参数"""
    DEBUG = True


class ProductionConfig(Config):
    """生产环境的配置参数"""
    pass


config = {
    "development": DevelopmentConfig,  # 开发模式
    "production": ProductionConfig  # 生产/线上模式
}


class RET:
    OK = "0"
    DBERR = "4001"
    NODATA = "4002"
    DATAEXIST = "4003"
    DATAERR = "4004"
    SESSIONERR = "4101"
    LOGINERR = "4102"
    PARAMERR = "4103"
    USERERR = "4104"
    ROLEERR = "4105"
    PWDERR = "4106"
    REQERR = "4201"
    IPERR = "4202"
    THIRDERR = "4301"
    IOERR = "4302"
    SERVERERR = "4500"
    UNKOWNERR = "4501"

# error_map = {
#     RET.OK: u"成功",
#     RET.DBERR: u"数据库查询错误",
#     RET.NODATA: u"无数据",
#     RET.DATAEXIST: u"数据已存在",
#     RET.DATAERR: u"数据错误",
#     RET.SESSIONERR: u"用户未登录",
#     RET.LOGINERR: u"用户登录失败",
#     RET.PARAMERR: u"参数错误",
#     RET.USERERR: u"用户不存在或未激活",
#     RET.ROLEERR: u"用户身份错误",
#     RET.PWDERR: u"密码错误",
#     RET.REQERR: u"非法请求或请求次数受限",
#     RET.IPERR: u"IP受限",
#     RET.THIRDERR: u"第三方系统错误",
#     RET.IOERR: u"文件读写错误",
#     RET.SERVERERR: u"内部错误",
#     RET.UNKOWNERR: u"未知错误",
# }
