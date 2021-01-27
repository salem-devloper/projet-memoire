"""
Pylot

Command line tool

pylot -c project_name

"""

import os
import argparse
import pkg_resources
import flask_pilot

PACKAGE = flask_pilot
CWD = os.getcwd()
PROJECTS_TEMPLATES = "skeleton"


def get_project_dir_path(project_name):
    return "%s/%s" % (CWD, project_name)

def copy_resource(src, dest):
    """
    To copy package data to destination
    """
    dest = (dest + "/" + os.path.basename(src)).rstrip("/")
    if pkg_resources.resource_isdir(PACKAGE.__name__, src):
        if not os.path.isdir(dest):
            os.makedirs(dest)
        for res in pkg_resources.resource_listdir(__name__, src):
            copy_resource(src + "/" + res, dest)
    else:
        if os.path.splitext(src)[1] not in [".pyc"]:
            with open(dest, "wb") as f:
                f.write(pkg_resources.resource_string(__name__, src))

def create_deployapp():
    pass

def create_project(project_name, template="default"):
    """
    Create the project
    """

    project_dir = get_project_dir_path(project_name)
    server_file = "%s/server_%s.py" % (CWD, project_name)
    server_tpl = pkg_resources.resource_string(__name__, '%s/server.py.tpl' % (PROJECTS_TEMPLATES))
    requirements_txt = "%s/requirements.txt" % CWD

    if not os.path.isdir(project_dir):
        os.makedirs(project_dir)
    else:
        raise OSError("Project directory '%s' exists already " % project_name)

    if not os.path.isfile(server_file):
        with open(server_file, "wb") as f:
            f.write(server_tpl.format(project_name=project_name))

    if not os.path.isfile(requirements_txt):
        with open(requirements_txt, "wb") as f:
            f.write("%s==%s" % (PACKAGE.NAME, PACKAGE.__version__))

    copy_resource("%s/%s/" % (PROJECTS_TEMPLATES, template), project_dir)


def main():
    try:
        parser = argparse.ArgumentParser(description="%s %s" % (PACKAGE.NAME, PACKAGE.__version__))
        parser.add_argument("-c", "--create", help="To create a new project."
                                 " [pylot -c project_name]")
        parser.add_argument("--admin", help="Create a project as admin "
                                            "[pylot -c project_name --admin]",
                            action="store_true" )

        arg = parser.parse_args()

        if arg.create:
            project_name = arg.create
            template = "admin" if arg.admin else "project"
            create_project(project_name, template)
            print("Pylot '%s' project created successfully " % project_name)
            print("Run server_%s.py to start the server" % project_name)


    except Exception as ex:
        print("ERROR: %s " % ex.__repr__())

