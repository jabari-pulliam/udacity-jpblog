"""
This module contains core base classes and utilities
"""

import os
import traceback
import hmac
from datetime import datetime
from functools import wraps

import logging
import webapp2
import jinja2

BASE_URL = '/'
SECRET = 'X9v1D171JvCdovjch9XT'
COOKIE_USERNAME = "username"


#
# Exceptions
#
class Error(Exception):
    def __init__(self, message):
        self.message = message


class NotAuthorizedException(Error):
    pass


class NotFoundException(Error):
    pass


class NotAuthenticatedException(Error):
    pass


#
# Custom Filters
#
def datetimeformat(value):
    now = datetime.now()
    if now.year != value.year:
        fmt_str = '%b %-d %Y'
    else:
        fmt_str = '%b %-d'
    return value.strftime(fmt_str)


class Handler(webapp2.RequestHandler):
    """
    The base request handler
    """
    TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')
    JINJA_ENV = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_DIR),
                                   autoescape=True)
    JINJA_ENV.filters['datetimeformat'] = datetimeformat

    def write(self, *a, **kw):
        """
        Writes a string to the response
        :param a:
        :param kw:
        :return:
        """
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        """
        Renders a template to a string
        :param template: The template path
        :param params: Template parameters
        :return: The rendered template
        """
        t = Handler.JINJA_ENV.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        """
        Renders a template to the response
        :param template: The template path
        :param kw: The template parameters
        :return:
        """
        # Pass the URL of the page that sent the request this response is to
        kw['request_url'] = self.request.url

        # Pass the username to the template if a user is logged in
        username = self.username
        if username:
            kw['current_user'] = username
        self.write(self.render_str(template, **kw))

    @classmethod
    def make_secure_val(cls, s):
        """
        Creates a tamper-proof string from the given value
        :param s: The value
        :return: A tamper-proof string
        """
        return '%s|%s' % (s, hmac.new(SECRET, s).hexdigest())

    @classmethod
    def check_secure_val(cls, s):
        """
        Verifies that the value encoded in the string has not been tampered
        with and returns it if it has not
        :param s:
        :return:
        """
        v = s.split('|')[0]
        if s == cls.make_secure_val(v):
            return v

    @property
    def username(self):
        """
        The username for the current user if one is logged in
        :return: The username or None
        """
        username = self.request.cookies.get(COOKIE_USERNAME)
        if username:
            username = Handler.check_secure_val(username)
            return username

    @username.setter
    def username(self, username):
        """
        Sets the username cookie
        :param username: The username
        :return:
        """
        self.response.set_cookie(COOKIE_USERNAME, Handler.make_secure_val(username))

    def logout(self):
        """
        Logs the user out
        :return:
        """
        self.response.delete_cookie(COOKIE_USERNAME)

    def handle_exception(self, exception, debug):
        page_title = 'Error'
        logging.log(logging.ERROR, traceback.format_exc())
        if isinstance(exception, NotFoundException):
            self.response.set_status(404, exception.message)
            self.render('error_page.html', page_title=page_title, error_message=exception.message)
        elif isinstance(exception, NotAuthorizedException):
            self.response.set_status(401, exception.message)
            self.render('error_page.html', page_title=page_title, error_message=exception.message)
        elif isinstance(exception, webapp2.HTTPException):
            self.response.set_status(exception.code, exception.message)
            self.render('error_page.html', page_title=page_title, error_message='Oops, something went wrong')
        else:
            self.response.set_status(500, exception.message)
            self.render('error_page.html', page_title=page_title, error_message='Oops, something went wrong')


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        handler = args[0]
        username = handler.username
        if not username:
            handler.redirect('/signin')
        else:
            return func(*args, **kwargs)
    return wrapper