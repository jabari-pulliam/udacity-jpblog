#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import hmac

import webapp2
import jinja2

from models import User
from models import BlogArticle

BASE_URL = '/'
SECRET = 'X9v1D171JvCdovjch9XT'
COOKIE_USERNAME = "username"

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


class Handler(webapp2.RequestHandler):
    """
    The base request handler
    """

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
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        """
        Renders a template to the response
        :param template: The template path
        :param kw: The template parameters
        :return:
        """
        username = self.username
        if username:
            jinja_env.globals['current_user'] = username
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

    def login(self, username, password):
        """
        Checks the username and possword and logs the user in.
        Returns True if successful and False otherwise.
        :param username: The username
        :param password:  The password
        :return: True if successful, False otherwise
        """
        user = User.find_by_username(username)
        if user and User.hash_password(password) == user.password:
            self.username = username
            return True
        return False

    def logout(self):
        """
        Logs the user out
        :return:
        """
        self.response.delete_cookie(COOKIE_USERNAME)

    def get_current_user(self):
        """
        Gets the user entity for the current user if one is logged in
        :return: The current user
        """
        username_cookie = self.request.cookies.get(COOKIE_USERNAME)
        username = self.check_secure_val(username_cookie)
        if username:
            return User.find_by_username(username)


class MainHandler(Handler):
    def get(self):
        self.render('home.html')


class SignInHandler(Handler):
    def get(self):
        if self.username:
            self.redirect('/')
        self.render('sign_in_form.html')

    def post(self):
        # Get the values from the form
        username = self.request.get('username')
        password = self.request.get('password')

        # Find a user with the username and verify the password
        if self.login(username, password):
            self.redirect('/')
        else:
            self.render('sign_in_form.html', error="Invalid username or password")


class LogoutHandler(Handler):
    def get(self):
        self.logout()
        self.redirect('/')


class SignUpHandler(Handler):
    def get(self):
        self.render('sign_up_form.html')

    def post(self):
        # Get the data from the request
        username = self.request.get('username')
        email = self.request.get('email')
        password = self.request.get('password')
        verify = self.request.get('verify')

        username_error = None
        email_error = None
        password_error = None
        verify_error = None

        # Validate the form input
        is_valid = True
        if not User.validate_username(username):
            is_valid = False
            username_error = 'Invalid username'

        if not User.validate_email(email):
            is_valid = False
            email_error = 'Invalid email'

        if not User.validate_password(password):
            is_valid = False
            password_error = 'Invalid password'

        if password != verify:
            is_valid = False
            verify_error = 'Passwords do not match'

        if is_valid:
            # Register the user and set the userid cookie
            User.register(username, email, password)
            self.username = username
            self.redirect('/')
        else:
            # Re-render the form with the error messages
            self.render('sign_up_form.html',
                        username=username,
                        email=email,
                        username_error=username_error,
                        email_error=email_error,
                        password_error=password_error,
                        verify_error=verify_error)


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/signup', SignUpHandler),
    ('/signin', SignInHandler),
    ('/logout', LogoutHandler)
], debug=True)
