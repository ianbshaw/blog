import os
import time
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2
import sys
sys.path.insert(1, 'C:\\Users\\ian\\appdata\\local\\Google\\Cloud SDK\\google-cloud-sdk\\platform\\google_appengine')
sys.path.insert(1, 'C:\\Users\\ian\\appdata\\local\\Google\\Cloud SDK\\google-cloud-sdk\\platform\\google_appengine\\lib\\yaml-3.10')
#sys.path.remove('C:\\Python27\\lib\\site-packages\\google')
import google

gae_dir = google.__path__.append('C:\\Program Files (x86)\\Google\\Cloud SDK\\google-cloud-sdk\\platform\\google_appengine\\google')
gae_dir = google.__path__.append('C:\\Users\\ian\\appdata\\local\\Google\\Cloud SDK\\google-cloud-sdk\\platform\\google_appengine\\google')
from google.appengine.ext import db


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'muaddib'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


def valid_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return username and USER_RE.match(username)


def valid_password(password):
    PASS_RE = re.compile(r"^.{3,20}$")
    return password and PASS_RE.match(password)


def valid_email(email):
    EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
    return not email or EMAIL_RE.match(email)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    likes = db.IntegerProperty(default=0)
    likedBy = db.ListProperty(long)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    user_id = db.IntegerProperty(required=True)
    image = db.StringProperty(required=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


class Comment(db.Model):
    """class that creates the basic database specifics for a comment"""
    comment = db.TextProperty(required=True)
    commenter = db.StringProperty(required=True)
    comment_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


class BlogHandler(webapp2.RequestHandler):
    """Main blog handler with convinience functions"""
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


class MainPage(BlogHandler):
    """Redirect for blank url"""
    def get(self):
        self.redirect("/blog")


class BlogFront(BlogHandler):
    """ Main blog page displaying most recent 10 posts"""
    def get(self):
        post = db.GqlQuery("select * from Post order by created desc limit 10")
        #c = db.GqlQuery("select count from Post")
        c = post.count()
        self.render('index.html', posts=post, c=int(c)) 


class PostPage(BlogHandler):
    """ Handler for single post entry page"""
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        comments = db.GqlQuery("select * from Comment order by " +
                               "created desc limit 10")
        post = db.get(key)
        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post, comments=comments)


class NewPost(BlogHandler):
    """ Handler for new post page"""
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')
        image = self.request.get('image')

        if subject and content and image:
            uid = self.user.key().id()
            p = Post(parent=blog_key(), subject=subject, content=content,
                     user_id=uid)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject, image and content, please!"
            self.render("newpost.html", subject=subject, content=content,
                        error=error)


class EditPost(BlogHandler):
    """ Handler for edit post page"""
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post is not None:
                if post.user_id == self.user.key().id():
                    self.render("editpost.html", subject=post.subject,
                                content=post.content)
                else:
                    self.redirect("/blog/" + post_id + "?error=You don't " +
                                  "have access to edit this record.")
            else:
                self.redirect("/blog/" + "?error=Record does not exist ")
        else:
            self.redirect("/login?error=You need to be logged, " +
                          "in order to edit your post!!")

    def post(self, post_id):
        if not self.user:
            return self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post and post.user_id == self.user.key().id():
                post.subject = subject
                post.content = content
                post.put()
                self.redirect('/blog/%s' % str(post.key().id()))
            else:
                    self.redirect("/blog/" + post_id + "?error=You don't " +
                                  "have access to edit this record.")
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content,
                        error=error)


class DeletePost(BlogHandler):
    """ Handler for deleting post entries"""
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post and post.user_id == self.user.key().id():
                post.delete()
                time.sleep(0.1)
                self.redirect("/blog")
            else:
                self.redirect("/blog/" + post_id + "?error=You don't have " +
                              "access to delete this record.")
        else:
            self.redirect("/login?error=You need to be logged, in order" +
                          " to delete your post!!")


class NewComment(BlogHandler):
    """ Handler for new post comment entry"""
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        p = db.get(key)

        if self.user:
            self.render("newcomment.html", p=p)
        else:
            error = "You need to be logged in to comment posts!"
            return self.render('login.html', error=error)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        p = db.get(key)

        commentin = self.request.get('comment')
        comment = commentin.replace('\n', '<br>')
        commenter = self.user.name
        comment_id = p.key().id()

        if self.user:
            if commenter and comment and comment_id:
                c = Comment(parent=blog_key(), comment=comment,
                            commenter=commenter, comment_id=comment_id)
                c.put()
                time.sleep(0.1)
                self.redirect("/blog/" + post_id)
            else:
                error = "You have to enter text in the comment field!"
                return self.render("newcomment.html", p=p, comment=comment,
                                   error=error)


class EditComment(BlogHandler):
    """ Handler for editing post comment entries"""
    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
        c = db.get(key)

        commented = c.comment.replace('<br>', '')

        if self.user:
            self.render("editcomment.html", c=c, commented=commented)
        else:
            error = "You need to be logged in to comment posts!"
            return self.render('login.html', error=error)

    def post(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
        c = db.get(key)

        if c is not None:
            commentin = self.request.get("comment")
            comment = commentin.replace('\n', '<br>')
            comment_id = c.comment_id
            commenter = c.commenter

            if self.user:
                if c.commenter == self.user.key().id():
                    if commenter and comment and comment_id:
                        c.comment = comment
                        c.commenter = commenter
                        c.put()
                        time.sleep(0.1)
                        self.redirect("/blog/" + str(c.comment_id))
                    else:
                        error = "You have to enter text in the comment field!"
                        return self.render("editcomment.html", c=c,
                                           commented=c.comment, error=error)
                else:
                    self.redirect("/blog/" + "?error=You don't have " +
                                  "access to edit this comment.")


class DeleteComment(BlogHandler):
    """ Handler for deleting post comment entries"""
    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
        c = db.get(key)

        if self.user:
            if c and self.user.name == c.commenter:
                c.delete()
                time.sleep(0.1)
                self.redirect("/blog/" + str(c.comment_id))
            else:
                error = "You can only delete your own posts!"
                return self.render("login.html", error=error)
        else:
            return self.redirect("/login")


class Like(BlogHandler):
    """ Handler for liking post entries"""
    def post(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            p = db.get(key)

            p.likes += 1
            p.likedBy.append(self.user.key().id())

            if p.user_id != self.user.key().id():
                if self.user.key().id() not in p.likedBy:
                    p.put()
                    time.sleep(0.1)
                    self.redirect('/blog/%s' % str(p.key().id()))
                else:
                    self.redirect('/blog/%s' % str(p.key().id()))


class Unlike(BlogHandler):
    """ Handler for unliking post entries"""
    def post(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            p = db.get(key)

            p.likes -= 1
            p.likedBy.remove(self.user.key().id())

            if p.user_id != self.user.key().id():
                p.put()
                time.sleep(0.1)
                self.redirect('/blog/%s' % str(p.key().id()))


class Signup(BlogHandler):
    """ Handler for user signup"""
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    """ Handler for registering users"""
    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')


class Login(BlogHandler):
    """Handler for user login"""
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):
    """Handler for user logout"""
    def get(self):
        self.logout()
        self.redirect('/blog')


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/delpost/([0-9]+)', DeletePost),
                               ('/blog/likepost/([0-9]+)', Like),
                               ('/blog/unlikepost/([0-9]+)', Unlike),
                               ('/blog/newcomment/([0-9]+)', NewComment),
                               ('/blog/deletecomment/([0-9]+)', DeleteComment),
                               ('/blog/editcomment/([0-9]+)', EditComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ],
                              debug=True)
