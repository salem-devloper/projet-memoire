"""
Flask-Pilot

config.py

This module contains config for different environment

Each class based on BaseConf is a different set of configuration for an active environment

For more config options: http://flask.pocoo.org/docs/0.10/config/

- How to use:

It's best to have a mechanism to differentiate dev from prod from staging etc

project_env = "Dev"

my_project = Pilot.init(Flask(__name__), config="config.%s" % project_env)

"""

from base_config import BaseConfig

class Dev(BaseConfig):
    """
    Development configuration
    """

    DEBUG = True
    SECRET_KEY = "PLEASE_CHANGE_SECRET_KEY"

class Prod(BaseConfig):
    """
    Production configuration
    """
    DEBUG = False
    SECRET_KEY = None




