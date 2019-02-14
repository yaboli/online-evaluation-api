import pymysql
import configparser


class SQLManager:
    def __init__(self):
        cf = configparser.ConfigParser()
        cf.read('db.ini')

        self.DATABASE = cf.get("db_info", "DATABASE")
        self.USER = cf.get("db_info", "USER")
        self.PASSWORD = cf.get("db_info", "PASSWORD")
        self.HOST = cf.get("db_info", "HOST")
        self.PORT = int(cf.get("db_info", "PORT"))

    def get_connect(self):
        conn = pymysql.connect(host=self.HOST, user=self.USER, passwd=self.PASSWORD, db=self.DATABASE,
                               port=self.PORT, charset='utf8')
        return conn

    # ------- 标注数据管理 -------
    def insert_new_data(self, dic):
        mark = 1

        user_id = dic["user_id"]
        time = dic["time"]
        text = dic["text"]

        # TODO: 插入标签序列

        sql_clause = 'insert into unit(user_id, time, text) VALUES (\'' + user_id + '\',\'' + time + '\',\'' + text + '\') '

        conn = self.get_connect()
        cursor = conn.cursor()
        try:
            cursor.execute(sql_clause)
            conn.commit()  # 这个对于增删改是必须的，否则事务没提交执行不成功
        except pymysql.Error as e:
            print(e)
            conn.rollback()
            mark = -1
        finally:
            # 关闭游标
            cursor.close()
            # 关闭数据库连接
            conn.close()
        return mark

    # ------- 用户管理 -------
