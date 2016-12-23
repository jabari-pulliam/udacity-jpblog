from core import Handler
from core import login_required
from core import NotAuthorizedException
from core import NotFoundException

from models import BlogPost

import use_cases


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
        post = use_cases.get_post_by_id(int(post_id))
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
            self.response.set_status(404, "No user found")
            self.render('error_page.html',
                        page_title='Error',
                        error_message="No user found")
        else:
            posts = use_cases.find_posts_by_created_by(user.key)
            self.render('home.html', page_title='My Posts', posts=posts)


class DeletePostHandler(Handler):
    @login_required
    def post(self, post_id):
        username = self.username
        try:
            use_cases.delete_post(int(post_id), username)
            self.redirect('/users/%s/posts' % username)
        except NotFoundException:
            self.response.set_status(404, "Post not found")
            self.render('error_page.html',
                        page_title="Error",
                        error_message="Post not found")
        except NotAuthorizedException:
            self.response.set_status(403, 'User not authorized')
            self.render('error_page.html',
                        page_title='Error',
                        error_message='User not authorized to delete this post')


class LikePostHandler(Handler):
    @login_required
    def post(self, post_id):
        try:
            use_cases.like_post(int(post_id), self.username)

            # Redirect the user back to the page that submitted the request
            self.redirect('/posts/%s' % post_id)
        except NotFoundException:
            self.response.set_status(404, "Post not found")
            self.render('error_page.html',
                        page_title="Error",
                        error_message="Post not found")


class EditPostHandler(Handler):
    @login_required
    def get(self, post_id):
        post = use_cases.get_post_by_id(int(post_id))
        if post:
            self.render('edit_post_form.html', page_title='Edit Post', post=post)
        else:
            self.render('error_page.html',
                        page_title="Error",
                        error_message="Post not found")

    @login_required
    def post(self, post_id):
        content = self.request.get('content').strip()
        title = self.request.get('title').strip()
        try:
            use_cases.edit_post(int(post_id), title, content, self.username)

            # Redirect the user back to the page that submitted the request
            self.redirect('/posts/%s' % post_id)
        except NotFoundException:
            self.response.set_status(404, 'Post not found')
            self.render('error_page.html',
                        page_title='Error',
                        error_message='Post not found')
        except NotAuthorizedException:
            self.response.set_status(403, 'User not authorized')
            self.render('error_page.html',
                        page_title='Error',
                        error_message='User not authorized to edit this post')
