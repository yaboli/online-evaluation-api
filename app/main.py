import sys
import logging
from flask import Flask, request
from sql_manager import SQLManager
import time
import datetime

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

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


@app.route("/")
def hello():
    version = "{}.{}".format(sys.version_info.major, sys.version_info.minor)
    message = "Hello World from Flask in a uWSGI Nginx Docker container with Python {} (default)".format(
        version
    )
    return message


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
    app.run(host="0.0.0.0", debug=True, port=80)
