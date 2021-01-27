"""
Utils
"""
from __future__ import division
import os
import re
import string
import random
import urlparse
import socket
import subprocess
import functools
import multiprocessing
import threading
from passlib.hash import sha256_crypt
import slugify
import jinja2


# ------------------------------------------------------------------------------
# Create a file on the production server called /.prod_env, to tell the system
# it is on PRODUCTION
PROD_ENV = True if os.path.isfile("/.prod_env") else False
STAGE_ENV = True if os.path.isfile("/.stage_env") else False

# ROOT DIRECTORY
ROOT_DIR = os.path.split(os.path.abspath(os.path.dirname(__file__)))[0]
# ------------------------------------------------------------------------------

def is_prod():
    """
    Return bool if the environment is Production or others
    :returns bool:
    """
    return PROD_ENV

def is_stage():
    """
    Return bool if the environment is Production or others
    :returns bool:
    """
    return STAGE_ENV

def is_dev():
    """
    Return if in DEV
    :return:
    """
    return True if not is_prod() and not is_stage() else False

def get_env():
    """
    Returns the environment
    :returns string:
    """

    if is_prod() and not is_stage(): # Staging server takes priority over prod for security purposes
        return "Prod"
    elif is_stage():
        return "Stage"
    else:
        return "Dev"


def get_config(config):
    """
    Return the config based on the environment

    usage:
    from utils import get_config  <- this module
    import conf.py <- your config file

    my_conf = get_config(conf)
    """
    return getattr(config, get_env())

# ------------------------------------------------------------------------------

def is_valid_email(email):
    """
    Check if email is valid
    """
    pattern = '[\w\.-]+@[\w\.-]+[.]\w+'
    return re.match(pattern, email)


def is_valid_password(password):
    """
    Check if a password is valid
    """
    pattern = re.compile(r"^.{4,25}$")
    return password and pattern.match(password)


def is_valid_url(url):
    """
    Check if url is valid
    """
    regex = re.compile(
            r'^(?:http|ftp)s?://' # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
            #r'localhost|' #localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
            r'(?::\d+)?' # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return bool(regex.match(url))


def get_domain_name(url):
    """
    Get the domain name
    :param url:
    :return:
    """
    if not url.startswith("http"):
        url = "http://" + url
    if not is_valid_url(url):
        raise ValueError("Invalid URL '%s'" % url)
    parse = urlparse.urlparse(url)
    return parse.netloc


def seconds_to_time(sec):
    """
    Convert seconds into time H:M:S
    """
    return "%02d:%02d" % divmod(sec, 60)


def time_to_seconds(t):
    """
    Convert time H:M:S to seconds
    """
    l = list(map(int, t.split(':')))
    return sum(n * sec for n, sec in zip(l[::-1], (1, 60, 3600)))

def to_slug(string):
    """
    Create a string to slug
    :param string:
    :return:
    """
    return slugify.slugify(string)


def hash_string(password):
    """
    Hash a string
    """
    return sha256_crypt.encrypt(password)


def verify_hash_string(password, pw_hash):
    """
    Verify string hash
    """
    return sha256_crypt.verify(password, pw_hash)


def generate_random_string(length=8):
    """
    Generate a random string
    """
    char_set = string.ascii_uppercase + string.digits
    return ''.join(random.sample(char_set * (length - 1), length))

def generate_random_hash(size=32):
    """
    Return a random hash key
    :param size: The max size of the hash
    :return: string
    """
    return os.urandom(size//2).encode('hex')

def format_number(value):
    """
    Format a number returns it with comma separated
    """
    return "{:,}".format(value)


def filter_stopwords(str):
    """
    Stop word filter
    returns list
    """
    STOPWORDS = ['a', 'able', 'about', 'across', 'after', 'all', 'almost',
                 'also', 'am', 'among', 'an', 'and', 'any', 'are', 'as', 'at',
                 'be', 'because', 'been', 'but', 'by', 'can', 'cannot',
                 'could', 'dear', 'did', 'do', 'does', 'either', 'else',
                 'ever', 'every', 'for', 'from', 'get', 'got', 'had', 'has',
                 'have', 'he', 'her', 'hers', 'him', 'his', 'how', 'however',
                 'i', 'if', 'in', 'into', 'is', 'it', 'its', 'just', 'least',
                 'let', 'like', 'likely', 'may', 'me', 'might', 'most', 'must',
                 'my', 'neither', 'no', 'nor', 'not', 'of', 'off', 'often',
                 'on', 'only', 'or', 'other', 'our', 'own', 'rather', 'said',
                 'say', 'says', 'she', 'should', 'since', 'so', 'some', 'than',
                 'that', 'the', 'their', 'them', 'then', 'there', 'these',
                 'they', 'this', 'tis', 'to', 'too', 'twas', 'us',
                 'wants', 'was', 'we', 'were', 'what', 'when', 'where',
                 'which', 'while', 'who', 'whom', 'why', 'will', 'with',
                 'would', 'yet', 'you', 'your']

    return [t for t in str.split() if t.lower() not in STOPWORDS]


def to_currency(amount, add_decimal=True):
    """
    Return the US currency format
    """
    return '{:1,.2f}'.format(amount) if add_decimal else '{:1,}'.format(amount)

def is_port_open(port, host="127.0.0.1"):
    """
    Check if a port is open
    :param port:
    :param host:
    :return bool:
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, int(port)))
        s.shutdown(2)
        return True
    except Exception as e:
        return False

def run(cmd):
    process = subprocess.Popen(cmd, shell=True,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    return process.communicate()[0].strip()


def convert_bytes(bytes):
    """
    Convert bytes into human readable
    """
    bytes = float(bytes)
    if bytes >= 1099511627776:
        terabytes = bytes / 1099511627776
        size = '%.2fT' % terabytes
    elif bytes >= 1073741824:
        gigabytes = bytes / 1073741824
        size = '%.2fG' % gigabytes
    elif bytes >= 1048576:
        megabytes = bytes / 1048576
        size = '%.2fM' % megabytes
    elif bytes >= 1024:
        kilobytes = bytes / 1024
        size = '%.2fK' % kilobytes
    else:
        size = '%.2fb' % bytes
    return size


def list_chunks(l, n):
    """
    Return a list of chunks
    :param l: List
    :param n: int The number of items per chunk
    :return: List
    """
    if n < 1:
        n = 1
    return [l[i:i + n] for i in range(0, len(l), n)]

def any_in_string(l, s):
    """
    Check if any items in a list is in a string
    :params l: dict
    :params s: string
    :return bool:
    """
    return any([i in l for i in l if i in s])

def add_path_to_jinja(flask_app, path):
    """
    To add path to jinja so it can be loaded
    :param flask_app:
    :param path:
    :return:
    """
    template_dir = path
    my_loader = jinja2.ChoiceLoader([
        flask_app.jinja_loader,
        jinja2.FileSystemLoader(template_dir)
    ])
    flask_app.jinja_loader = my_loader

# ------------------------------------------------------------------------------
# Background multi processing and threading
# Use the decorators below for background processing

def bg_process(func):
    """
    A multiprocess decorator
    :param func:
    :return:
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        p = multiprocessing.Process(target=func, args=args, kwargs=kwargs)
        p.start()
    return wrapper

def bg_thread(func):
    """
    A threading decorator
    :param func:
    :return:
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        p = threading.Thread(target=func, args=args, kwargs=kwargs)
        p.start()
    return wrapper


def connect_redis(dsn):
    """
    Return the redis connection
    :param dsn: The dsn url
    :return: Redis
    """
    import redis
    return redis.StrictRedis.from_url(url=dsn)
