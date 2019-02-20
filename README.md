# 智能审校线上评测系统

本项目为智能审校算法模型接口的测试平台，评测者可以对测试效果不佳的数据进行标注/编辑，新标注的数据将会自动存入数据库。

## 安装prerequisites

```
pip install -r requirements.txt
```

## 数据库迁移

项目开发者可以在app/db_models.py中修改或直接迁移源代码中定义好的Schema，步骤如下所述：

1. 在本地创建一个MySQL Schema
2. 修改app/config.py中Config的"SQLALCHEMY_DATABASE_URI"参数，使其指向本地Schema
3. 在command line中进入项目directory，并输入如下指令：

```
set FLASK_APP=app/db_models.py
```
```
flask db init
```
```
flask db migrate
```
```
flask db upgrade
```
