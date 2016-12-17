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

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    @classmethod
    def make_secure_val(cls, s):
        return '%s|%s' % (s, hmac.new(SECRET, s))

    @classmethod
    def check_secure_val(cls, s):
        v = s.split('|')[0]
        if s == cls.make_secure_val(v):
            return v

    def set_auth_cookie(self, user_id):
        self.response.set_cookie("userid", Handler.make_secure_val(user_id))

    def login(self, username, password):
        pass

    def logout(self):
        self.response.delete_cookie("userid")
        self.redirect('/')

    def get_current_user(self):
        userid_cookie = self.request.cookies.get('userid')
        user_key = self.check_secure_val(userid_cookie)
        if user_key:
            return User.get_from_urlsafe_key(user_key)


class MainHandler(Handler):
    def get(self):
        self.render('home.html')


class SignUpHandler(Handler):
    def get(self):
        self.render('signup_form.html')

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
        is_valid = False
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
            user = User.register(username, email, password)
            self.set_auth_cookie(user.get_urlsafe_key())
            self.redirect('/')
        else:
            # Re-render the form with the error messages
            self.render('signup_form.html',
                        username=username,
                        email=email,
                        username_error=username_error,
                        email_error=email_error,
                        password_error=password_error,
                        verify_error=verify_error)

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/signup', SignUpHandler)
], debug=True)
