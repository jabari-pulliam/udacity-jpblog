#!/usr/bin/env python
"""
This module is the main entry point to the application and performs
application setup.
"""

import webapp2

from handlers import DeleteCommentHandler
from handlers import DeletePostHandler
from handlers import EditCommentHandler
from handlers import EditPostHandler
from handlers import LikePostHandler
from handlers import LogoutHandler
from handlers import MainHandler
from handlers import NewCommentHandler
from handlers import NewPostHandler
from handlers import SignInHandler
from handlers import SignUpHandler
from handlers import UserPostsHandler
from handlers import ViewPostHandler


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/signup', SignUpHandler),
    ('/signin', SignInHandler),
    ('/logout', LogoutHandler),
    ('/posts/new', NewPostHandler),
    webapp2.Route('/posts/<post_id>', ViewPostHandler),
    webapp2.Route('/users/<username>/posts', UserPostsHandler),
    webapp2.Route('/posts/<post_id>/delete', DeletePostHandler),
    webapp2.Route('/posts/<post_id>/like', LikePostHandler),
    webapp2.Route('/posts/<post_id>/edit', EditPostHandler),
    webapp2.Route('/posts/<post_id>/comment/new', NewCommentHandler),
    webapp2.Route('/comments/<comment_id>/edit', EditCommentHandler),
    webapp2.Route('/comments/<comment_id>/delete', DeleteCommentHandler),
], debug=True)
