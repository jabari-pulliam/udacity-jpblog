"""
This module contains the request handlers
"""

import use_cases
from core import Handler
from core import NotFoundException
from core import NotAuthorizedException
from core import login_required
from models import BlogPost


class MainHandler(Handler):
    def get(self):
        # Get all of the posts
        posts = BlogPost.query().fetch()

        self.render('home.html', page_title='Home', posts=posts)


class SignInHandler(Handler):
    def get(self):
        if self.username:
            self.redirect('/')
        self.render('sign_in_form.html', page_title='Sign In')

    def post(self):
        # Get the values from the form
        username = self.request.get('username')
        password = self.request.get('password')

        # Find a user with the username and verify the password
        if use_cases.login(username, password):
            self.username = username
            self.redirect('/')
        else:
            self.render('sign_in_form.html', page_title='Sign In',
                        error="Invalid username or password")


class LogoutHandler(Handler):
    def get(self):
        self.logout()
        self.redirect('/')


class SignUpHandler(Handler):
    def get(self):
        self.render('sign_up_form.html', page_title='Sign Up')

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
        if not use_cases.validate_username(username):
            is_valid = False
            username_error = 'Invalid username'

        if not use_cases.validate_user_email(email):
            is_valid = False
            email_error = 'Invalid email'

        if not use_cases.validate_user_password(password):
            is_valid = False
            password_error = 'Invalid password'

        if password != verify:
            is_valid = False
            verify_error = 'Passwords do not match'

        if is_valid:
            # Register the user and set the userid cookie
            use_cases.register_user(username, email, password)
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


class ViewPostHandler(Handler):
    def get(self, post_id):
        post = use_cases.get_post_by_id(long(post_id))
        if post:
            self.render('view_post.html', page_title=post.title, post=post)


class NewPostHandler(Handler):
    @login_required
    def get(self):
        self.render('new_post_form.html', page_title='New Post')

    @login_required
    def post(self):
        title = self.request.get("title").strip()
        content = self.request.get("content").strip()

        post_id = use_cases.create_new_post(title, content, self.username)
        self.redirect("/posts/%s" % post_id)


class UserPostsHandler(Handler):
    def get(self, username):
        user = use_cases.get_user_by_username(username)
        if not user:
            raise NotFoundException(message='User not found')
        else:
            posts = use_cases.find_posts_by_created_by(user.key)
            self.render('home.html', page_title='My Posts', posts=posts)


class DeletePostHandler(Handler):
    @login_required
    def post(self, post_id):
        username = self.username
        use_cases.delete_post(long(post_id), username)
        self.redirect('/users/%s/posts' % username)


class LikePostHandler(Handler):
    @login_required
    def post(self, post_id):
        use_cases.like_post(long(post_id), self.username)

        # Redirect the user back to the page that submitted the request
        self.redirect('/posts/%s' % post_id)


class EditPostHandler(Handler):
    @login_required
    def get(self, post_id):
        post = use_cases.get_post_by_id(int(post_id))
        if post:
            if post.created_by.id() == self.username:
                self.render('edit_post_form.html', page_title='Edit Post', post=post)
            else:
                raise NotAuthorizedException('You are not authorized to edit this post')
        else:
            raise NotFoundException(message='Post not found')

    @login_required
    def post(self, post_id):
        content = self.request.get('content').strip()
        title = self.request.get('title').strip()
        use_cases.edit_post(long(post_id), title, content, self.username)

        # Redirect the user back to the page that submitted the request
        self.redirect('/posts/%s' % post_id)


class NewCommentHandler(Handler):
    @login_required
    def get(self, post_id):
        post = use_cases.get_post_by_id(long(post_id))
        self.render('new_comment_form.html', post=post)

    @login_required
    def post(self, post_id):
        body = self.request.get('body').strip()
        use_cases.add_comment_to_post(long(post_id), body, self.username)
        self.redirect('/posts/%s' % post_id)


class EditCommentHandler(Handler):
    @login_required
    def get(self, comment_id):
        comment = use_cases.get_comment_by_id(long(comment_id))
        if not comment:
            raise NotFoundException('Comment not found')

        if comment.created_by.id() != self.username:
            raise NotAuthorizedException('You are not authorized to edit this comment')

        post = use_cases.get_post_by_id(comment.post.id())
        if not post:
            raise NotFoundException('Post not found')

        self.render('edit_comment_form.html', comment=comment, post=post)

    @login_required
    def post(self, comment_id):
        comment_body = self.request.get('body').strip()
        use_cases.edit_comment(long(comment_id), comment_body, self.username)
        comment = use_cases.get_comment_by_id(long(comment_id))
        self.redirect('/posts/%s' % comment.post.id())


class DeleteCommentHandler(Handler):
    @login_required
    def get(self, comment_id):
        comment_id = long(comment_id)
        post_id = use_cases.delete_comment(comment_id)
        self.redirect('/posts/%s' % post_id)
