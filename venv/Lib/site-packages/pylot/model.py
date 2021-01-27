
import datetime
import utils

class ModelError(Exception):
    pass

# user_mixin create a mixin to create user login
def user_mixin(db):
    """
    UserMixin
    :params db: active_sqlalchemy
    """
    class UserMixin(object):
        """An admin user capable of viewing reports.

        :param str email: email address of user
        :param str password: encrypted password for the user

        """

        ROLE_USER = "USER"
        ROLE_ADMIN = "ADMIN"
        ROLE_SUPERADMIN = "SUPERADMIN"

        STATUS_ACTIVE = "ACTIVE"
        STATUS_SUSPENDED = "SUSPENDED"

        all_roles = [ROLE_USER, ROLE_ADMIN, ROLE_SUPERADMIN]
        all_status = [STATUS_ACTIVE, STATUS_SUSPENDED]

        email = db.Column(db.String(75), index=True, unique=True)
        email_confirmed = db.Column(db.Boolean, default=False)
        password_hash = db.Column(db.String(250))
        require_password_change = db.Column(db.Boolean, default=False)
        reset_password_token = db.Column(db.String(100))
        name = db.Column(db.String(250))
        role = db.Column(db.String(25), default=ROLE_USER)
        status = db.Column(db.String(25), default=STATUS_ACTIVE)
        is_loggedin = db.Column(db.Boolean, default=False)
        profile_pic_url = db.Column(db.String(250))
        signup_method = db.Column(db.String(250))
        last_login = db.Column(db.DateTime)
        last_visited = db.Column(db.DateTime)


        # ------ FLASK-LOGIN REQUIRED METHODS ----------------------------------

        def is_active(self):
            """True, as all users are active."""
            return True

        def get_id(self):
            """Return the id """
            return self.id

        def is_authenticated(self):
            """Return True if the user is authenticated."""
            return True

        def is_anonymous(self):
            """ False, as anonymous users aren't supported."""
            return False
        # ---------- END FLASK-LOGIN REQUIREMENTS ------------------------------

        @classmethod
        def get_by_email(cls, email):
            """
            Find by email. Useful for logging in users
            """
            return cls.all().filter(cls.email == email).first()

        @classmethod
        def new(cls, email, password=None, **kwargs):
            """
            Register a new user
            """
            account = cls.get_by_email(email)
            if account:
                raise ModelError("User exists already")
            account = cls.create(email=email)
            if password:
                account.set_password(password)
            if "role" not in kwargs:
                kwargs["role"] = cls.ROLE_USER
            if kwargs:
                account.update(**kwargs)
            return account

        def password_matched(self, password):
            """
            Check if the password matched the hash
            :returns bool:
            """
            return utils.verify_hash_string(password, self.password_hash)

        def set_password(self, password):
            """
            Encrypt the password and save it in the DB
            """
            self.update(password_hash=utils.hash_string(password))

        def set_random_password(self):
            """
            Set a random password, saves it and return the readable string
            :returns string:
            """
            password = utils.generate_random_string()
            self.set_password(password)
            return password

        def set_require_password_change(self, req=True):
            """
            Set the require password change ON/OFF
            :params req: bool
            """
            self.update(require_password_change=req)

        def set_role(self, role):
            """
            Set account role
            """
            self.update(role=role)

        def update_last_login(self):
            """
            TO update the last login
            :return:
            """
            self.update(last_login=datetime.datetime.now())

        def update_last_visited(self):
            """
            Update last visited
            :return:
            """
            self.update(last_visited=datetime.datetime.now())

    return UserMixin

# The user_model create a fully built model with social signin
def user_model(db):

    UserMixin = user_mixin(db)

    class User(UserMixin, db.Model):

        @classmethod
        def oauth_register(cls, provider, provider_user_id=None,
                          email=None, name=None, image_url=None,
                          **kwargs):
            """
            Register
            :param provider:
            :param provider_user_id:
            :param email:
            :param name:
            :param image_url:
            :param kwargs:
            :return:
            """
            oal = UserOauthLogin
            oauthuser = oal.all()\
                .filter(oal.provider == provider)\
                .filter(oal.provider_user_id == provider_user_id)\
                .first()
            if oauthuser:
                return oauthuser.user
            else:
                if not email:
                    raise ModelError("Email is missing")

                data = {
                    "provider": provider,
                    "provider_user_id": provider_user_id,
                    "email": email,
                    "name": name,
                    "image_url": image_url
                }

                user = User.get_by_email(email)
                if user:
                    data.update({"user_id": user.id})
                    oal.create(**data)
                    return user
                else:
                    user = User.new(email=email,
                                    name=name,
                                    profile_pic_url=image_url,
                                    signin_method=provider)
                    data.update({"user_id": user.id})
                    oal.create(**data)
                    return user

        def oauth_connect(self, provider, provider_user_id=None,
                          email=None, name=None, image_url=None,
                          **kwargs):
            """
            Connect an account an OAUTH
            :param provider:
            :param provider_user_id:
            :param email:
            :param name:
            :param image_url:
            :param kwargs:
            :return:
            """
            oal = UserOauthLogin
            oauthuser = oal.all()\
                .filter(oal.provider == provider)\
                .filter(oal.provider_user_id == provider_user_id)\
                .first()
            if oauthuser:
                if oauthuser.user_id == self.id:
                    return self
                else:
                    raise ModelError("Account is already linked to another user")
            else:
                data = {
                    "provider": provider,
                    "provider_user_id": provider_user_id,
                    "email": email,
                    "name": name,
                    "image_url": image_url,
                    "user_id": self.id
                }
                oal.create(**data)
                return self


    class UserOauthLogin(db.Model):
        user_id = db.Column(db.Integer, db.ForeignKey(User.id))
        provider = db.Column(db.String(50), index=True)
        provider_user_id = db.Column(db.String(250))
        name = db.Column(db.String(250))
        email = db.Column(db.String(250))
        image_url = db.Column(db.String(250))
        access_token = db.Column(db.String(250))
        secret = db.Column(db.String(250))
        profile_url = db.Column(db.String(250))

        user = db.relationship(User, backref="oauth_logins")

    return User
