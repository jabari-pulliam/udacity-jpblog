"""
This module contains the business rules for the application
"""

from google.appengine.ext import ndb

from core import NotAuthorizedException
from core import NotFoundException

from models import User
from models import BlogPost
from models import Comment


def login(username, password):
    """
    Perform login
    :param username: The username
    :param password: The password
    :return: True if login was successful, False otherwise
    """
    user = User.find_by_username(username)
    if user and User.hash_password(password) == user.password:
        return True
    return False


def get_user_by_username(username):
    """
    Retrieves a user model by its username
    :param username: The username
    :return: The user
    """
    return User.get_by_id(username)


def get_post_by_id(post_id):
    """
    Retrieves a blog post by ID
    :param post_id: The post ID
    :return: The blog post
    """
    post = BlogPost.get_by_id(post_id)

    return BlogPost.get_by_id(post_id)


def register_user(username, email, password):
    """
    Registers a new user and returns the user if it was successful
    :param username: The username
    :param email: The email
    :param password: The password
    :return: The user or None if unsuccessful
    """
    return User.register(username, email, password)


def validate_username(username):
    """
    Validate the username. Ensures that the name is unique.
    :param username: The username
    :return: True if the username is valid, False otherwise
    """
    key = ndb.Key(User, username)
    user = key.get()
    if user:
        return False
    return User.USERNAME_PATTERN.match(username)


def validate_user_password(password):
    """
    Validate the user password
    :param password: The password
    :return: True if the password is valid
    """
    return User.PASSWORD_PATTERN.match(password)


def validate_user_email(email):
    """
    Validate the user email
    :param email: The email
    :return: True if the email is valid
    """
    return User.EMAIL_PATTERN.match(email)


def find_posts_by_created_by(user_key):
    """
    Retrieves all posts created by the user
    :param user_key: The user's key
    :return: A list of posts
    """
    return ndb.gql('SELECT * FROM BlogPost WHERE created_by = :1', user_key).fetch()


def create_new_post(title, content, username):
    """
    Creates and returns a new post
    :param title: The title
    :param content: The content
    :param username: The creator's username
    :return: The post's ID
    """
    user_key = ndb.Key(User, username)
    post = BlogPost.create(title, content, user_key)
    return post.key.id()


def delete_post(post_id, username):
    """
    Deletes a post
    :param post_id: The post's ID
    :param username: The username of the user performing the delete
    :return:
    """
    post = get_post_by_id(post_id)
    if not post:
        raise NotFoundException('Post not found')
    if post.created_by.id() != username:
        raise NotAuthorizedException('User is not authorized to delete this post')

    # Delete the post's comments
    ndb.delete_multi(post.comment_keys)

    post.key.delete()


def add_comment_to_post(post_id, comment_text, username):
    """
    Adds a comment to a post
    :param post_id: The post's ID
    :param comment_text: The text of the comment
    :param username: The username of the commenter
    :return:
    """
    post = BlogPost.get_by_id(post_id)
    user = User.get_by_id(username)
    if post and user:
        comment = Comment.create(text=comment_text, post_key=post.key, created_by_key=user.key)
        post.add_comment(comment.key)
        post.put()
    else:
        raise NotFoundException('Post or user not found')


def get_comment_by_id(comment_id):
    """
    Retrieves a comment by its ID
    :param comment_id: The ID
    :return: The comment
    """
    return Comment.get_by_id(comment_id)


def edit_comment(comment_id, text, username):
    """
    Edits a comment
    :param comment_id: The comment's ID
    :param text: The new text
    :param username: The username of the current user
    :return:
    """
    comment = Comment.get_by_id(comment_id)
    if not comment:
        raise NotFoundException('Comment not found')

    if comment.created_by.id() != username:
        raise NotAuthorizedException('User not authorized to edit this comment')

    comment.text = text
    comment.put()


def delete_comment(comment_id, current_user):
    """
    Delete a comment
    :param comment_id: The comment
    :return: The ID of the comment's post
    """
    # Find the comment if is exists
    comment = Comment.get_by_id(comment_id)
    if not comment:
        raise NotFoundException('Comment not found')

    if comment.created_by.id() != current_user:
        raise NotAuthorizedException('You are not authorized to delete this comment')

    # Find the post if it exists
    post = comment.post.get()
    if not post:
        raise NotFoundException('Post not found')

    # Remove the comment from the post
    post.comment_keys.remove(comment.key)
    post.put()

    # Delete the comment
    comment.key.delete()

    return post.key.id()


def like_post(post_id, username):
    """
    Add a like to a post
    :param post_id: The post's ID
    :param username: The username of the user liking the post
    :return:
    """
    post = get_post_by_id(post_id)
    if post:
        user_key = ndb.Key(User, username)
        if post.created_by.id() != username and user_key not in post.liked_by:
            post.liked_by.append(ndb.Key(User, username))
            post.put()
    else:
        raise NotFoundException('Post not found')


def edit_post(post_id, title, content, username):
    """
    Edits an existing post
    :param post_id: The post's ID
    :param title The post's title
    :param content: The new content
    :param username: The username of the user who is editing
    :return:
    """
    post = get_post_by_id(post_id)
    if post:
        if post.created_by.id() == username:
            post.title = title
            post.content = content
            post.put()
        else:
            raise NotAuthorizedException('User is not authorized to edit this post')
    else:
        raise NotFoundException('Post not found')
