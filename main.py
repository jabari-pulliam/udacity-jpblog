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
import re
import hmac

import webapp2
import jinja2

import models

BASE_URL = '/'
SECRET = 'X9v1D171JvCdovjch9XT'
USERNAME_PATTERN = re.compile("^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_PATTERN = re.compile("^.{3,20}$")
EMAIL_PATTERN = re.compile("^[\S]+@[\S]+.[\S]+$")

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


class MainHandler(webapp2.RequestHandler):
    def get(self):
        self.response.write('Hello world!')


app = webapp2.WSGIApplication([
    ('/', MainHandler)
], debug=True)
