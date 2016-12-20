import re
import hmac
from google.appengine.ext import ndb


USERNAME_PATTERN = re.compile("^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_PATTERN = re.compile("^.{3,20}$")
EMAIL_PATTERN = re.compile("^[\S]+@[\S]+.[\S]+$")


class User(ndb.Model):
    """
    A user entity. The username is the key.
    """

    username = ndb.StringProperty(required=True)
    email = ndb.StringProperty(required=True)
    password = ndb.StringProperty(required=True)

    PASSWORD_SALT = 'X9v1D171JvCdovjch9XT'

    @classmethod
    def register(cls, username, email, password):
        password = cls.hash_password(password)
        user = cls(username=username,
                   email=email,
                   password=password)

        # Set the username as the key
        user.key = ndb.Key(cls, username)

        user.put()
        return user

    @classmethod
    def validate_username(cls, username):
        key = ndb.Key(cls, username)
        user = key.get()
        if user:
            return False
        return USERNAME_PATTERN.match(username)

    @classmethod
    def validate_password(cls, password):
        return PASSWORD_PATTERN.match(password)

    @classmethod
    def validate_email(cls, email):
        return EMAIL_PATTERN.match(email)

    @classmethod
    def find_by_username(cls, username):
        key = ndb.Key(cls, username)
        return key.get()

    @classmethod
    def hash_password(cls, password):
        return hmac.new(User.PASSWORD_SALT, password).hexdigest()


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

