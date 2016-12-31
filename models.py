"""
This module contains the models for the application
"""

import re
import hmac
from google.appengine.ext import ndb


class User(ndb.Model):
    """
    A user entity. The username is the key.
    """
    username = ndb.StringProperty(required=True)
    email = ndb.StringProperty(required=True)
    password = ndb.StringProperty(required=True)

    PASSWORD_SALT = 'X9v1D171JvCdovjch9XT'
    USERNAME_PATTERN = re.compile("^[a-zA-Z0-9_-]{3,20}$")
    PASSWORD_PATTERN = re.compile("^.{3,20}$")
    EMAIL_PATTERN = re.compile("^[\S]+@[\S]+.[\S]+$")

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
    def find_by_username(cls, username):
        key = ndb.Key(cls, username)
        return key.get()

    @classmethod
    def hash_password(cls, password):
        return hmac.new(User.PASSWORD_SALT, password).hexdigest()

    @classmethod
    def make_key(cls, username):
        return ndb.Key(cls, username)


class Comment(ndb.Model):
    """
    Comment on a blog post
    """
    created_by = ndb.KeyProperty(required=True)
    post = ndb.KeyProperty(required=True)
    text = ndb.TextProperty(required=True)
    created_at = ndb.DateTimeProperty(auto_now_add=True)
    last_modified_at = ndb.DateTimeProperty(auto_now=True)

    @classmethod
    def create(cls, text, post_key, created_by_key):
        """
        Creates a new comment
        :param text: The comment text
        :param post_key: The ID of the comment's post
        :param created_by_key: The ID of the commenter
        :return: The comment
        """
        comment = cls(text=text, post=post_key, created_by=created_by_key)
        comment.put()
        return comment


class BlogPost(ndb.Model):
    """
    A blog post
    """
    title = ndb.StringProperty(required=True)
    created_at = ndb.DateTimeProperty(auto_now_add=True)
    last_modified_at = ndb.DateTimeProperty(auto_now=True)
    content = ndb.TextProperty(required=True)
    created_by = ndb.KeyProperty(required=True)
    liked_by = ndb.KeyProperty(repeated=True)
    comment_keys = ndb.KeyProperty(repeated=True)

    @classmethod
    def create(cls, title, content, user):
        """
        Creates a new blog post
        :param title: The title
        :param content: The post content
        :param user: The key of the user
        :return:
        """
        post = cls(title=title, content=content, created_by=user, liked_by=[], comment_keys=[])
        post.put()
        return post

    @property
    def comments(self):
        return ndb.get_multi(self.comment_keys)

    def add_comment(self, comment):
        self.comment_keys.append(comment)
