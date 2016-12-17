from google.appengine.ext import ndb


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

