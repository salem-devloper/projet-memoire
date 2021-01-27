
import os

# ------------------------------------------------------------------------------
# ENVIRONMENT FOR CONFIG
# Flask-Pilot uses configuration class by default, ie: Prod(), Dev(), (Stage()).
# To switch from one config to another based on the environment we are on,
#
# The methods below will check the type of environment.
#
# The rules below are not a requirement, but a suggestion. You can place your
# files wherever you like.
#
# Create a file on the production server called /.prod_env, to tell the system
# it is on PRODUCTION. /.stage_env for STAGING.
# By default it will fallback to Dev
#
# ------------------------------------------------------------------------------
PROD_ENV = True if os.path.isfile("/.prod_env") else False
STAGE_ENV = True if os.path.isfile("/.stage_env") else False

def is_prod_env():
    return PROD_ENV

def is_stage_env():
    return STAGE_ENV

def is_dev_env():
    return True if not is_prod_env() and not is_stage_env() else False

def get_env():
    """
    Return the string value of the environment: Prod | Stage | Dev
    """
    # Staging server takes priority over prod for security purposes
    if is_prod_env() and not is_stage_env():
        return "Prod"
    elif is_stage_env():
        return "Stage"
    else:
        return "Dev"

def get_config_env(config):

    return getattr(config, get_env())

# ------------------------------------------------------------------------------
