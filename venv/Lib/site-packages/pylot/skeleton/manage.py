"""
::Flask-Pilot::

manage.py

Command line tool to manage your application

"""

import argparse
from base_config import BaseConfig
from {project_name} import model


NAME = "Flask-Pilot Manager"
__version__ = BaseConfig.APP_VERSION


def setup():
    """
    Setup and create the first user
    """
    model.db.create_all()
    email = BaseConfig.ADMIN_EMAIL
    name = BaseConfig.ADMIN_NAME
    user = model.User.all().filter(model.User.email == email).first()
    if not user:
        model.User.create(email=email,
                          name=name,
                          role=model.User.ROLE_SUPERADMIN)


def main():
    parser = argparse.ArgumentParser(description="%s  v.%s" % (NAME, __version__))
    parser.add_argument("--setup", help="Setup the system",  action="store_true")
    arg = parser.parse_args()

    if arg.setup:
        print("Setting up...")
        setup()


if __name__ == "__main__":
    main()


