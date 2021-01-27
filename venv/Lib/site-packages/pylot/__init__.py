"""
Flask-Pilot

"""

import os
from hashlib import sha1
import time
import base64
import hmac
import urllib
import pkg_resources
import functools
import re
import datetime
import humanize
import jinja2

from werkzeug.contrib.fixers import ProxyFix
from flask_classy import FlaskView, route  # flask-classy
import inspect

from flask import (abort, redirect, request, render_template, flash,
                   url_for, jsonify, session)
from flask_login import (LoginManager, login_required, login_user,
                         logout_user, current_user)

from flask_assets import (Environment, Bundle)

from flask_recaptcha import ReCaptcha
from ses_mailer import TemplateMail

from flask_kvsession import KVSessionExtension
from simplekv.memory.redisstore import RedisStore

from flask_wtf import Form
from wtforms import SelectField

import utils


# ------------------------------------------------------------------------------
NAME = "Flask-Pylot"
__author__ = "Mardix"
__license__ = "MIT"
__copyright__ = "(c) 2015 Mardix"

# ------------------------------------------------------------------------------

# Flash Messages: error, success, info
def flash_error(message):
    """
    Set an `error` flash message
    :param message: string - The message
    """
    flash(message, "error")


def flash_success(message):
    """
    Set a `success` flash message
    :param message: string - The message
    """
    flash(message, "success")


def flash_info(message):
    """
    Set an `info` flash message
    :param message: string - The message
    """
    flash(message, "info")

# ------------------------------------------------------------------------------

class Pylot(FlaskView):
    """
    Pilot a FlaskView extension
    """
    LAYOUT = "layout.html"  # The default layout
    assets = None
    _app = None
    _bind_app = set()
    _global_context = dict(
        title="",
        description="",
        url="",
        image="",
        site_name="",
        object_type="",
        locale="",
        keywords=[],
        use_opengraph=True,
        use_googleplus=True,
        use_twitter=""
    )

    @classmethod
    def init(cls, app, directory=None, config=None):
        """
        Allow to register all subclasses of Pilot
        So we call it once initiating
        :param app: Flask instance
        :param directory: The directory containing your project's Views, Templates and Static
        :param config: string of config object. ie: "app.config.Dev"
        """

        app.wsgi_app = ProxyFix(app.wsgi_app)

        if config:
            app.config.from_object(config)

        app.template_folder = directory + "/templates"
        app.static_folder = directory + "/static"

        cls._app = app
        cls.assets = Environment(cls._app)

        for _app in cls._bind_app:
            _app(cls._app)

        for subcls in cls.__subclasses__():
            subcls.register(cls._app)

        return cls._app

    @classmethod
    def bind(cls, app):
        """
        To bind application that needs the 'app' object to init
        :param app: callable function that will receive 'Flask.app' as first arg
        """
        if not hasattr(app, "__call__"):
            raise TypeError("From Pilot.bind: '%s' is not callable" % app)
        cls._bind_app.add(app)

    @classmethod
    def get_config(cls, key, default=None):
        """
        Shortcut to access the config in your class
        :param key: The key to access
        :param default: The default value when None
        :returns mixed:
        """
        return cls._app.config.get(key, default)

    @classmethod
    def __(cls, **kwargs):
        """
        Assign a global view context to be used in the template
        :params **kwargs:
        """
        cls._global_context.update(kwargs)

    @classmethod
    def __meta(cls, **kwargs):
        """
        Meta allows you to add meta data to site
        :params **kwargs:

        meta keys we're expecting:
            title (str)
            description (str)
            url (str) (Will pick it up by itself if not set)
            image (str)
            site_name (str) (but can pick it up from config file)
            object_type (str)
            keywords (list)
            locale (str)

            **Boolean By default these keys are True
            use_opengraph
            use_twitter
            use_googleplus

        """
        _name_ = "meta"
        meta_data = cls._global_context.get(_name_, {})
        for k, v in kwargs.items():
            # Prepend/Append string
            if (k.endswith("__prepend") or k.endswith("__append")) \
                    and  isinstance(v, str):
                k, position = k.split("__", 2)
                _v = meta_data.get(k, "")
                if position == "prepend":
                    v = _v + v
                elif position == "append":
                    v += _v
            if k == "keywords" and not isinstance(k, list):
                raise ValueError("Meta keyword must be a list")
            meta_data[k] = v
        cls.__(_name_=meta_data)

    @classmethod
    def render(cls, data={}, view_template=None, layout=None, **kwargs):
        """
        To render data to the associate template file of the action view
        :param data: The context data to pass to the template
        :param view_template: The file template to use. By default it will map the classname/action.html
        :param layout: The body layout, must contain {% include __view_template__ %}
        """
        if not view_template:
            stack = inspect.stack()[1]
            module = inspect.getmodule(cls).__name__
            module_name = module.split(".")[-1]
            action_name = stack[3]      # The method being called in the class
            view_name = cls.__name__    # The name of the class without View

            if view_name.endswith("View"):
                view_name = view_name[:-4]
            view_template = "%s/%s.html" % (view_name, action_name)

        data = data if data else dict()
        data["__"] = cls._global_context if cls._global_context else {}
        if kwargs:
            data.update(kwargs)

        data["__view_template__"] = view_template

        return render_template(layout or cls.LAYOUT, **data)

# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------

class MetaDataMixin(object):
    pass

class AppError(Exception):
    """ For exception in application pages """
    pass


def with_user_roles(roles):
    """
    with_user_roles(roles)

    It allows to check if a user has access to a view by adding the decorator
    with_user_roles([])

    Requires flask-login

    In your model, you must have a property 'role', which will be invoked to
    be compared to the roles provided.

    If current_user doesn't have a role, it will throw a 403

    If the current_user is not logged in will throw a 401

    * Require Flask-Login
    ---
    Usage

    @app.route('/user')
    @login_require
    @with_user_roles(['admin', 'user'])
    def user_page(self):
        return "You've got permission to access this page."
    """
    def wrapper(f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            if current_user.is_authenticated():
                if not hasattr(current_user, "role"):
                    raise AttributeError("<'role'> doesn't exist in login 'current_user'")
                if current_user.role not in roles:
                    return abort(403)
            else:
                return abort(401)
            return f(*args, **kwargs)
        return wrapped
    return wrapper


class InitPilot(object):
    def __init__(self, app):
        self.app = app
        self.register_templates()
        self.setup_config()
        self.init_session()

    def setup_config(self):
        _pilot = {}
        for k, v in self.app.config.items():
            if k.startswith("PILOT_"):
                _pilot[k] = v

        # OAUTH LOGIN
        if self.app.config.get("PILOT_USER_LOGIN_OAUTH_ENABLE"):
            _sl = self.app.config.get("PILOT_USER_LOGIN_OAUTH_CREDENTIALS")
            if _sl and isinstance(_sl, dict):
                client_ids = {}
                buttons = []
                for name, prop in _sl.items():
                    if isinstance(prop, dict):
                        if prop["ENABLE"]:
                            _name = name.lower()
                            client_ids[_name] = prop["CLIENT_ID"]
                            buttons.append(_name)
                _pilot["login_oauth_credentials"] = {
                    "client_ids": client_ids,
                    "buttons": buttons
                }
        Pilot.__(pilot=_pilot,
                 year=datetime.datetime.now().year)

    def register_templates(self):
        # Register the templates
        path = pkg_resources.resource_filename(__name__, "templates")
        utils.add_path_to_jinja(self.app, path)

        # Register Assets
        _dir_ = os.path.dirname(__file__)
        env = Pilot.assets
        env.load_path = [
            Pilot._app.static_folder,
            os.path.join(_dir_, 'static'),
        ]
        env.register(
            'pilot_js',
            Bundle(
                "pilot/js/s3upload.js",
                "pilot/js/hello.js",
                "pilot/js/pilot.js",
                output='pilot.js'
            )
        )
        env.register(
            'pilot_css',
            Bundle(
                'pilot/css/pilotlib_style.css',
                'pilot/css/bootstrap-social-btns.css',
                output='pilot.css'
            )
        )

    def init_session(self):

        store = None
        backend = self.app.config.get("PILOT_SESSION_BACKEND")
        if backend:
            backend = backend.upper()
            if backend == "REDIS":
                dsn = self.app.config.get("PILOT_SESSION_DSN")
                _redis = utils.connect_redis(dsn)
                store = RedisStore(_redis)
        if store:
            KVSessionExtension(store, self.app)

Pilot.bind(InitPilot)

# ------------------------------------------------------------------------------


class S3UploadMixin(object):
    """
    This mixin allow you to upload file directly to S3 using javascript
    """

    def sign_s3_upload(self):
        """
        Allow to create Signed object to upload to S3 via JS
        """
        AWS_ACCESS_KEY = self.get_config('PILOT_AWS_ACCESS_KEY')
        AWS_SECRET_KEY = self.get_config('PILOT_AWS_SECRET_KEY')
        S3_BUCKET = self.get_config('PILOT_AWS_S3_BUCKET')

        object_name = request.args.get('s3_object_name')
        mime_type = request.args.get('s3_object_type')
        expires = long(time.time()+10)
        amz_headers = "x-amz-acl:public-read"
        put_request = "PUT\n\n%s\n%d\n%s\n/%s/%s" % (mime_type, expires, amz_headers, S3_BUCKET, object_name)
        signature = base64.encodestring(hmac.new(AWS_SECRET_KEY, put_request, sha1).digest())
        signature = urllib.quote(urllib.quote_plus(signature.strip()))
        url = 'https://s3.amazonaws.com/%s/%s' % (S3_BUCKET, object_name)
        return jsonify({
            'signed_request': '%s?AWSAccessKeyId=%s&Expires=%d&Signature=%s' % (url, AWS_ACCESS_KEY, expires, signature),
             'url': url
          })

# ------------------------------------------------------------------------------


def login_view(model,
          logout_view=None,
          signin_view=None,
          login_message="Please Login",
          allow_signup=True,
          view_template=None):

    """
    :params model: The user model instance active-sqlachemy
    :view: The base view
    :logout_view: The view after logout
    :signin_view: The view after sign in
    :login_message: The message to show when login
    :allow_signup: To allow signup on the page
    :param view_template: The directory containing the view pages

    Doc:
    Login is a view that allows you to login/logout use.
    You must create a Pilot view called `Login` to activate it

    LoginView = app.views.login(model=model.User, signin_view="Account:index")
    class Login(LoginView, Pilot):
        route_base = "/account"


    """

    User = model
    tmail = TemplateMail()
    recaptcha = ReCaptcha()

    # Login

    login_view = "Login:login"
    login_manager = LoginManager()
    login_manager.login_view = login_view
    login_manager.login_message = login_message
    login_manager.login_message_category = "error"

    # Start binding
    Pilot.bind(tmail.init_app)
    Pilot.bind(model.db.init_app)
    Pilot.bind(login_manager.init_app)
    Pilot.bind(recaptcha.init_app)


    @login_manager.user_loader
    def load_user(userid):
        return User.get(userid)

    if not view_template:
        view_template = "PilotTemplates/Login"
    template_page = view_template + "/%s.html"

    class Login(S3UploadMixin):
        route_base = "/"

        SESSION_KEY_SET_EMAIL_DATA = "set_email_tmp_data"

        @classmethod
        def signup_handler(cls):
            """
            To handle the signup process. Must still bind to the app
             :returns User object:
            """
            if request.method == "POST":
                name = request.form.get("name")
                email = request.form.get("email")
                password = request.form.get("password")
                password2 = request.form.get("password2")
                profile_pic_url = request.form.get("profile_pic_url", None)

                if not name:
                    raise UserWarning("Name is required")
                elif not utils.is_valid_email(email):
                    raise UserWarning("Invalid email address '%s'" % email)
                elif not password.strip() or password.strip() != password2.strip():
                    raise UserWarning("Passwords don't match")
                elif not utils.is_valid_password(password):
                    raise UserWarning("Invalid password")
                else:
                    return User.new(email=email,
                                    password=password.strip(),
                                    name=name,
                                    profile_pic_url=profile_pic_url,
                                    signup_method="EMAIL")

        @classmethod
        def change_login_handler(cls, user_context=None, email=None):
            if not user_context:
                user_context = current_user
            if not email:
                email = request.form.get("email").strip()

            if not utils.is_valid_email(email):
                raise UserWarning("Invalid email address '%s'" % email)
            else:
                if email != user_context.email and User.get_by_email(email):
                    raise UserWarning("Email exists already '%s'" % email)
                elif email != user_context.email:
                    user_context.update(email=email)
                    return True
            return False

        @classmethod
        def change_password_handler(cls, user_context=None, password=None,
                                    password2=None):
            if not user_context:
                user_context = current_user
            if not password:
                password = request.form.get("password").strip()
            if not password2:
                password2 = request.form.get("password2").strip()

            if password:
                if password != password2:
                    raise UserWarning("Password don't match")
                elif not utils.is_valid_password(password):
                    raise UserWarning("Invalid password")
                else:
                    user_context.set_password(password)
                    return True
            else:
                raise UserWarning("Password is empty")

        @classmethod
        def reset_password_handler(cls, user_context=None, send_notification=False):
            """
            Reset the password
            :returns string: The new password string
            """
            if not user_context:
                user_context = current_user

            new_password = user_context.set_random_password()

            if send_notification:
                tmail.send("reset-password",
                           to=user_context.email,
                           new_password=new_password,
                           name=user_context.name,
                           login_url=url_for(login_manager.login_view, _external=True)
                           )
            return new_password

        def _can_login(self):
            if not self.get_config("PILOT_USER_LOGIN_EMAIL_ENABLE"):
                abort(403)

        def _can_oauth_login(self):
            if not self.get_config("PILOT_USER_LOGIN_OAUTH_ENABLE"):
                abort(403)

        def _can_signup(self):
            if not self.get_config("PILOT_USER_LOGIN_SIGNUP_ENABLE"):
                abort(403)

        # --- LOGIN
        def login(self):
            """
            Login page
            """
            self._can_login()
            logout_user()

            return self.render(login_url_next=request.args.get("next", ""),
                               view_template=template_page % "login")

        @route("email-login", methods=["POST"])
        def email_login(self):
            """
            login via email
            """
            self._can_login()

            email = request.form.get("email").strip()
            password = request.form.get("password").strip()

            if not email or not password:
                flash_error("Email or Password is empty")
                return redirect(url_for(login_view, next=request.form.get("next")))
            account = User.get_by_email(email)
            if account and account.password_matched(password):
                login_user(account)
                account.update_last_login()
                account.update_last_visited()
                return redirect(request.form.get("next") or url_for(signin_view))
            else:
                flash_error("Email or Password is invalid")
                return redirect(url_for(login_view, next=request.form.get("next")))

        # OAUTH Login
        @route("oauth-login", methods=["POST"])
        def oauth_login(self):
            """
            To login via social
            """
            self._can_oauth_login()

            email = request.form.get("email").strip()
            name = request.form.get("name").strip()
            provider = request.form.get("provider").strip()
            provider_user_id = request.form.get("provider_user_id").strip()
            image_url = request.form.get("image_url").strip()
            next = request.form.get("next", "")
            # save to session and redirect to enter email address
            if not email:
                session[self.SESSION_KEY_SET_EMAIL_DATA] = {
                    "type": "social_login",
                    "email": email,
                    "name": name,
                    "provider": provider,
                    "provider_user_id": provider_user_id,
                    "image_url": image_url,
                    "next": next,
                    "signup_method": "SOCIAL:%s" % provider.upper()
                }
                return redirect(url_for("Login:set_email", next=request.form.get("next", "")))
            else:
                user = User.oauth_register(provider=provider,
                                         provider_user_id=provider_user_id,
                                         email=email,
                                         name=name,
                                         image_url=image_url,
                                         signup_method="SOCIAL:%s" % provider.upper())
                if user:
                    login_user(user)
                    user.update_last_login()
                    user.update_last_visited()
                    return redirect(request.form.get("next") or url_for(signin_view))

            return redirect(url_for(login_view, next=request.form.get("next", "")))

        # OAUTH Login
        @route("oauth-connect", methods=["POST"])
        @login_required
        def oauth_connect(self):
            """
            To login via social
            """
            email = request.form.get("email").strip()
            name = request.form.get("name").strip()
            provider = request.form.get("provider").strip()
            provider_user_id = request.form.get("provider_user_id").strip()
            image_url = request.form.get("image_url").strip()
            next = request.form.get("next", "")
            try:
                current_user.oauth_connect(provider=provider,
                                         provider_user_id=provider_user_id,
                                         email=email,
                                         name=name,
                                         image_url=image_url)
            except Exception as ex:
                flash_error("Unable to link your account")

            return redirect(url_for("Login:account_settings"))

        # --- LOGOUT
        def logout(self):
            logout_user()
            flash_success("Logout successfully!")
            return redirect(url_for(logout_view or login_view))

        # --- LOST PASSWORD
        @route("lost-password")
        def lost_password(self):
            self._can_login()
            logout_user()
            return self.render(view_template=template_page % "lost_password")

        @route("lost-passwordp", methods=["POST"])
        def lost_password_post(self):
            self._can_login()
            email = request.form.get("email")
            user = User.get_by_email(email)
            if user:
                self.reset_password_handler(user_context=user,
                                            send_notification=True)
                flash_success("A new password has been sent to '%s'" % email)
            else:
                flash_error("Invalid email address")
            return redirect(url_for(login_view))

        @route("set-email")
        def set_email(self):
            self._can_login()
            return self.render(view_template=template_page % "set_email")

        @route("set-emailp", methods=["POST"])
        def set_emailp(self):
            self._can_login()
            email = request.form.get("email")
            if not utils.is_valid_email(email):
                flash_error("Invalid email address '%s'" % email)
                return redirect(url_for(login_view))

            if email and self.SESSION_KEY_SET_EMAIL_DATA in session:
                _data = session[self.SESSION_KEY_SET_EMAIL_DATA]
                user = User.get_by_email(email)
                if user:
                    flash_error("An account is already using '%s'" % email)
                else:
                    User.new(email=email,
                             name=_data["name"],
                             signup_method=_data["signup_method"] if "signup_method" in _data else "" )

                    if "type" in _data:
                        if _data["type"] == "social_login":
                            user = User.social_login(provider=_data["provider"],
                                                     provider_user_id=_data["provider_user_id"],
                                                     email=email,
                                                     name=_data["name"],
                                                     image_url=_data["image_url"])
                            return redirect(request.form.get("next") or url_for(signin_view))

                return redirect(url_for("Login:set_email", next=request.form.get("next", "")))

        # --- RESET PASSWORD
        def reset_password(self, token):
            pass

        # --
        def signup(self):
            self._can_login()
            self._can_signup()

            logout_user()
            return self.render(login_url_next=request.args.get("next", ""),
                               view_template=template_page % "signup")

        @route("signupp", methods=["POST"])
        def signup_post(self):
            self._can_login()
            self._can_signup()

            # reCaptcha
            if not recaptcha.verify():
                flash_error("Invalid Security code")
                return redirect(url_for("Login:signup", next=request.form.get("next")))
            try:
                new_account = self.signup_handler()
                login_user(new_account)
                flash_success("Congratulations! ")
                return redirect(request.form.get("next") or url_for(signin_view))
            except Exception as ex:
                flash_error(ex.message)
            return redirect(url_for("Login:signup", next=request.form.get("next")))

        # --------

        @route("/account-settings")
        @login_required
        def account_settings(self):
                return self.render(view_template=template_page % "account_settings")

        @route("/change-login", methods=["POST"])
        @login_required
        def change_login(self):
            confirm_password = request.form.get("confirm-password").strip()
            try:
                if current_user.password_matched(confirm_password):
                    self.change_login_handler()
                    flash_success("Login Info updated successfully!")
                else:
                    flash_error("Invalid password")
            except Exception as ex:
                flash_error("Error: %s" % ex.message)
            return redirect(url_for("Login:account_settings"))

        @route("/change-password", methods=["POST"])
        @login_required
        def change_password(self):
            try:
                confirm_password = request.form.get("confirm-password").strip()
                if current_user.password_matched(confirm_password):
                    self.change_password_handler()
                    flash_success("Password updated successfully!")
                else:
                    flash_error("Invalid password")
            except Exception as ex:
                flash_error("Error: %s" % ex.message)
            return redirect(url_for("Login:account_settings"))

        @route("/change-info", methods=["POST"])
        @login_required
        def change_info(self):
            name = request.form.get("name").strip()
            profile_pic_url = request.form.get("profile_pic_url").strip()

            data = {}
            if name and name != current_user.name:
                data.update({"name": name})
            if profile_pic_url:
                data.update({"profile_pic_url": profile_pic_url})
            if data:
                current_user.update(**data)
                flash_success("Account info updated successfully!")
            return redirect(url_for("Login:account_settings"))

        @route("/change-profile-pic", methods=["POST"])
        @login_required
        def change_profile_pic(self):
            profile_pic_url = request.form.get("profile_pic_url").strip()
            _ajax = request.form.get("_ajax", None)
            if profile_pic_url:
                current_user.update(profile_pic_url=profile_pic_url)
            if _ajax:
                return jsonify({})
            return redirect(url_for("Login:account_settings"))
    return Login

# ------------------------------------------------------------------------------


def user_admin_view(model, login_view, view_template=None):
    """
    :param model: The User class model
    :param login_view: The login view interface
    :param view_template: The directory containing the view pages
    :return: UserAdmin

    Doc:
    User Admin is a view that allows you to admin users.
    You must create a Pilot view called `UserAdmin` to activate it

    UserAdmin = app.views.user_admin(User, Login)
    class UserAdmin(UserAdmin, Pilot):
        pass

    The user admin create some global available vars under '__.user_admin'

    It's also best to add some security access on it
    class UserAdmin(UserAdmin, Pilot):
        decorators = [login_required]

    You can customize the user info page (::get) by creating the directory in your
    templates dir, and include the get.html inside of it

    ie:
    >/admin/templates/UserAdmin/get.html

    <div>
        {% include "PilotTemplates/UserAdmin/get.html" %}
    <div>

    <div>Hello {{ __.user_admin.user.name }}<div>

    """
    User = model
    LoginView = login_view

    if not view_template:
        view_template = "PilotTemplates/UserAdmin"
    template_page = view_template + "/%s.html"

    class AdminForm(Form):
        """
        Help create a simple form
        """
        user_role = SelectField(choices=[(role, role) for i, role in enumerate(User.all_roles)])
        user_status = SelectField(choices=[(status, status) for i, status in enumerate(User.all_status)])

    class UserAdmin(object):
        route_base = "user-admin"

        @classmethod
        def search_handler(cls, per_page=20):
            """
            To initiate a search
            """
            page = request.args.get("page", 1)
            show_deleted = True if request.args.get("show-deleted") else False
            name = request.args.get("name")
            email = request.args.get("email")

            users = User.all(include_deleted=show_deleted)
            users = users.order_by(User.name.asc())
            if name:
                users = users.filter(User.name.contains(name))
            if email:
                users = users.filter(User.email.contains(email))

            users = users.paginate(page=page, per_page=per_page)

            cls.__(user_admin=dict(
                form=AdminForm(),
                users=users,
                search_query={
                       "excluded_deleted": request.args.get("show-deleted"),
                       "role": request.args.get("role"),
                       "status": request.args.get("status"),
                       "name": request.args.get("name"),
                       "email": request.args.get("email")
                    }
                ))
            return users

        @classmethod
        def get_user_handler(cls, id):
            """
            Get a user
            """
            user = User.get(id, include_deleted=True)
            if not user:
                abort(404, "User doesn't exist")
            cls.__(user_admin=dict(user=user, form=AdminForm()))
            return user

        def index(self):
            self.search_handler()
            return self.render(view_template=template_page % "index")

        def get(self, id):
            self.get_user_handler(id)
            return self.render(view_template=template_page % "get")

        def post(self):
            try:
                id = request.form.get("id")
                user = User.get(id, include_deleted=True)
                if not user:
                    flash_error("Can't change user info. Invalid user")
                    return redirect(url_for("UserAdmin:index"))

                delete_entry = True if request.form.get("delete-entry") else False
                if delete_entry:
                    user.update(status=user.STATUS_SUSPENDED)
                    user.delete()
                    flash_success("User DELETED Successfully!")
                    return redirect(url_for("UserAdmin:get", id=id))

                email = request.form.get("email")
                password = request.form.get("password")
                password2 = request.form.get("password2")
                name = request.form.get("name")
                role = request.form.get("user_role")
                status = request.form.get("user_status")
                upd = {}
                if email and email != user.email:
                    LoginView.change_login_handler(user_context=user)
                if password and password2:
                    LoginView.change_password_handler(user_context=user)
                if name != user.name:
                    upd.update({"name": name})
                if role and role != user.role:
                    upd.update({"role": role})
                if status and status != user.status:
                    if user.is_deleted and status == user.STATUS_ACTIVE:
                        user.delete(False)
                    upd.update({"status": status})
                if upd:
                    user.update(**upd)
                flash_success("User's Info updated successfully!")

            except Exception as ex:
                flash_error("Error: %s " % ex.message)
            return redirect(url_for("UserAdmin:get", id=id))


        @route("reset-password", methods=["POST"])
        def reset_password(self):
            try:
                id = request.form.get("id")
                user = User.get(id)
                if not user:
                    flash_error("Can't reset password. Invalid user")
                    return redirect(url_for("User:index"))

                password = LoginView.reset_password_handler(user_context=user,
                                                        send_notification=True)
                flash_success("User's password reset successfully!")
            except Exception as ex:
                flash_error("Error: %s " % ex.message)
            return redirect(url_for("UserAdmin:get", id=id))

        @route("create", methods=["POST"])
        def create(self):
            try:
                account = LoginView.signup_handler()
                account.set_role(request.form.get("role", "USER"))
                flash_success("User created successfully!")
                return redirect(url_for("UserAdmin:get", id=account.id))
            except Exception as ex:
                flash_error("Error: %s" % ex.message)
            return redirect(url_for("UserAdmin:index"))

    return UserAdmin

# ------------------------------------------------------------------------------


def error_view(view_template=None):
    """
    Create the Error view
    Must be instantiated

    import error_view
    ErrorView = error_view()

    :param view_template: The directory containing the view pages
    :return:
    """
    if not view_template:
        view_template = "PilotTemplates/Error"

    template_page = "%s/index.html" % view_template

    class Error(Pilot):
        """
        Error Views
        """
        @classmethod
        def register(cls, app, **kwargs):
            super(cls, cls).register(app, **kwargs)

            @app.errorhandler(400)
            def error_400(error):
                return cls.index(error, 400)

            @app.errorhandler(401)
            def error_401(error):
                return cls.index(error, 401)

            @app.errorhandler(403)
            def error_403(error):
                return cls.index(error, 403)

            @app.errorhandler(404)
            def error_404(error):
                return cls.index(error, 404)

            @app.errorhandler(500)
            def error_500(error):
                return cls.index(error, 500)

            @app.errorhandler(503)
            def error_503(error):
                return cls.index(error, 503)

        @classmethod
        def index(cls, error, code):
            cls.__(page_title="Error %s" % code)

            return cls.render(error=error, view_template=template_page), code
    return Error
ErrorView = error_view()

# ------------------------------------------------------------------------------


def contact_view(view_template=None):
    if not view_template:
        view_template = "PilotTemplates/Contact"

    template_page = "%s/index.html" % view_template


def maintenance_view(view_template=None):
    """
    Create the Maintenance view
    Must be instantiated

    import maintenance_view
    MaintenanceView = maintenance_view()

    :param view_template: The directory containing the view pages
    :return:
    """
    if not view_template:
        view_template = "PilotTemplates/Maintenance"

    template_page = "%s/index.html" % view_template

    class Maintenance(Pilot):
        def __init__(self, *args, **kwargs):
            if self.get_config("PILOT_MAINTENANCE_ON"):
                @self._app.before_request
                def before_request():
                    return self.index()

        def index(self):
            self.__(page_title="Under Maintenance")
            return self.render(layout=template_page), 503

    return Maintenance

MaintenanceView = maintenance_view()


# ------------------------------------------------------------------------------

# Extend JINJA Filters
def to_date(dt, format="%m/%d/%Y"):
    return dt.strftime(format)

def strip_decimal(amount):
    return amount.split(".")[0]

def bool_to_yes(b):
    return "Yes" if b is True else "No"

def bool_to_int(b):
    return 1 if b is True else 0

def nl2br(s):
    """
    {{ s|nl2br }}

    Convert newlines into <p> and <br />s.
    """
    if not isinstance(s, basestring):
        s = str(s)
    s = re.sub(r'\r\n|\r|\n', '\n', s)
    paragraphs = re.split('\n{2,}', s)
    paragraphs = ['<p>%s</p>' % p.strip().replace('\n', '<br />') for p in paragraphs]
    return '\n\n'.join(paragraphs)


jinja2.filters.FILTERS.update({
    "currency": utils.to_currency,
    "strip_decimal": strip_decimal,
    "date": to_date,
    "int": int,
    "slug": utils.to_slug,
    "intcomma": humanize.intcomma,
    "intword": humanize.intword,
    "naturalday": humanize.naturalday,
    "naturaldate": humanize.naturaldate,
    "naturaltime": humanize.naturaltime,
    "naturalsize": humanize.naturalsize,
    "bool_to_yes": bool_to_yes,
    "bool_to_int": bool_to_int,
    "nl2br": nl2br
})
