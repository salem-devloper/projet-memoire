"""
Flask-Pilot models

model.py

You may place your models here.
"""

import flask_pilot.model
from active_sqlalchemy import SQLAlchemy
from . import get_config_env
import config

conf = get_config_env(config)

db = SQLAlchemy(conf.SQLALCHEMY_DATABASE_URI)

UserMixin = flask_pilot.model.user_mixin(db)
class User(UserMixin, db.Model):
    pass
