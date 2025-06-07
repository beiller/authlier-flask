from functools import wraps

import json
from typing import TypedDict
import urllib.request

from werkzeug.local import Local, LocalProxy

# Create a context-local storage
_local = Local()

# Define a proxy that accesses _local.user
current_user = LocalProxy(lambda: getattr(_local, 'user', None))

class AuthlierException(Exception): pass

class AuthlierManager():
    def __init__(self, _api_key: str, _api_secret: str):
        global api_key, api_secret
        api_key = _api_key
        api_secret = _api_secret
    def init_app(self, app):
        pass
    def user_identity_loader(self, func):
        global user_identity_loader
        user_identity_loader = func
        return func
    def user_lookup_loader(self, func):
        global user_lookup_loader
        user_lookup_loader = func
        return func
    def get_context(self, func):
        global get_context
        get_context = func
        return func
    def get_token(self, func):
        global get_token
        get_token = func
        return func
    


class AuthlierResponse(TypedDict):
  id: str 
  username: str
  site: str
  is_active: bool # true,
  is_verified: bool # true,
  metadata: str
  email: str
  phone: str


def default_get_context():
    from flask import request
    return request.headers


def default_get_token(context):
    assert hasattr(context, 'get')
    headerval = context.get("Authorization", None)
    if headerval is None: return None
    try:
        desc, token = headerval.split(' ')
        assert desc.lower() == header_field.lower()
    except (ValueError, AssertionError):
        return None
    return token


def default_user_identity_loader(user_object):
    return str(getattr(user_object, "id", None))


def default_user_lookup_loader(_primary_key):
    return None


user_identity_loader = default_user_identity_loader
user_lookup_loader = default_user_lookup_loader
get_context = default_get_context
get_token = default_get_token
header_name = "Authorization"
header_field = "Bearer"
api_key = None
api_secret = None


def http_request(url: str, method='POST', post_data=None):
    conditionsSetURL = f'https://authlier.com{url}'
    params = None
    if post_data:
        params = json.dumps(post_data).encode('utf8')
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Secret-Key": api_secret,
        'content-type': 'application/json'
    }
    try:
        req = urllib.request.Request(conditionsSetURL, method=method, data=params, headers=headers)
        response = urllib.request.urlopen(req)
    except urllib.error.HTTPError as e:
        raise AuthlierException(e)
    response = response.read()
    try:
        response = json.loads(response)
    except json.decoder.JSONDecodeError:
        return response
    return response


def authlier_required(optional=False):    
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_authlier_in_request(optional)
            # Requires flask >= 2.0
            return fn(*args, **kwargs)  # pragma: no cover

        return decorator

    return wrapper


def verify_authlier_in_request(optional=False):
    context = get_context()
    token = get_token(context)
    if token is None or not isinstance(token, str) or len(token) < 32:
        if not optional:
            raise AuthlierException(context, token)
        return None
    try:
        response = http_request("/v1/user_authenticate/", "POST", {"token": token})
        _local.user = user_lookup_loader(response["metadata"])
    except AuthlierException as e:
        if optional is False:
            raise AuthlierException(context, None, token)
        _local.user = None

    if optional is False and _local.user is None:
        raise AuthlierException(context, response, token)

    return _local.user

AuthlierToken = str

def login(username: str, password: str) -> AuthlierToken:
    response = http_request("/v1/user_authenticate/", "PATCH", {"username": username, "password": password})
    _local.user = user_lookup_loader(response["metadata"])
    return response["token"]

def register(user, username: str, password: str) -> AuthlierToken:
    identifier = user_identity_loader(user)
    response = http_request("/v1/siteuser/", "POST", {"username": username, "password": password, "metadata": identifier, "email": username})
    _local.user = user_lookup_loader(response["metadata"])
    return response["token"]

def logout(token) -> bool:
    http_request("/v1/user_authenticate/", "DELETE", {"token": token})
    _local.user = None
    return True

def forgot_password(email: str) -> bool:
    http_request("/v1/user_password_reset/", "POST", {"email": email})
    return True


