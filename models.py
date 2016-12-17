import re
from google.appengine.ext import ndb


USERNAME_PATTERN = re.compile("^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_PATTERN = re.compile("^.{3,20}$")
EMAIL_PATTERN = re.compile("^[\S]+@[\S]+.[\S]+$")


class User(ndb.Model):
    username = ndb.StringProperty(required=True)
    email = ndb.StringProperty(required=True)
    password = ndb.StringProperty(required=True)

    @classmethod
    def register(cls, username, email, password):
        user = cls(username=username,
                   email=email,
                   password=password)
        user.put()
        return user

    @classmethod
    def validate_username(cls, username):
        return USERNAME_PATTERN.match(username)

    @classmethod
    def validate_password(cls, password):
        return PASSWORD_PATTERN.match(password)

    @classmethod
    def validate_email(cls, email):
        return EMAIL_PATTERN.match(email)

    @classmethod
    def get_from_urlsafe_key(cls, urlsafe_key):
        key = ndb.Key(urlsafe=urlsafe_key)
        if key:
            return key.get()

    def get_urlsafe_key(self):
        return self.key.urlsafe()


class BlogArticle(ndb.Model):
    title = ndb.StringProperty(required=True)
    created_at = ndb.DateTimeProperty(auto_now_add=True)
    last_modified_at = ndb.DateTimeProperty(auto_now=True)
    content = ndb.TextProperty(required=True)
    created_by = ndb.KeyProperty(required=True)

    @classmethod
    def create(cls, title, content, user):
        article = cls(title=title, content=content, created_by=user.key)
        article.put()
        return article

