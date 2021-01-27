"""
::Flask-Pilot::

Base config file

"""

class BaseConfig(object):
    """
    Base config
    More config -> http://flask.pocoo.org/docs/0.10/config/
    """
    ADMIN_EMAIL = ""
    ADMIN_NAME = ""

    SERVER_NAME = None
    DEBUG = True
    SECRET_KEY = None

    # Flask-SQLAlchemy : http://pythonhosted.org/Flask-SQLAlchemy/config.html
    SQLALCHEMY_DATABASE_URI = None

    # Flask-Assets : http://flask-assets.readthedocs.org/
    ASSETS_DEBUG = False
    FLASK_ASSETS_USE_S3 = False

    # Flask-Mail : http://pythonhosted.org/Flask-Mail/
    MAIL_SERVER = 'localhost'
    MAIL_PORT = 25
    MAIL_USE_TLS = False
    MAIL_USE_SSL = False
    MAIL_DEBUG = False
    MAIL_USERNAME = None
    MAIL_PASSWORD = None
    MAIL_DEFAULT_SENDER = None
    MAIL_MAX_EMAILS = None
    MAIL_ASCII_ATTACHMENTS = False

    # Flask-ReCaptcha
    RECAPTCHA_SITE_KEY = ""
    RECAPTCHA_SECRET_KEY = ""
