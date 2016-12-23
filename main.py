#!/usr/bin/env python

import webapp2

from handlers import MainHandler
from handlers import SignInHandler
from handlers import SignUpHandler
from handlers import LogoutHandler
from handlers import NewPostHandler
from handlers import ViewPostHandler
from handlers import UserPostsHandler
from handlers import DeletePostHandler
from handlers import LikePostHandler
from handlers import EditPostHandler


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
], debug=True)
