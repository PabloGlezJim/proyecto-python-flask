from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, CreateRegisterForm, CreateLoginForm, CreateCommentForm
from flask_gravatar import Gravatar
from functools import wraps


app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Create USER LOADER
login_manager = LoginManager()
login_manager.init_app(app)

# Gravatar
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# Create admin Decorator


def decorator_admin(function):
    @wraps(function)
    def wrapper_function(*args, **kwargs):
        admin = current_user.get_id()
        if admin is not None:
            admin = int(admin)
            if admin == 1:
                return function(*args, **kwargs)
            else:
                return abort(403)
        else:
            return abort(403)
    return wrapper_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# CONFIGURE TABLES


class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(220), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    blog_post = relationship("BlogPost", back_populates="user")
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    user_author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = relationship("User", back_populates="blog_post")
    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    test = db.Column(db.Text, nullable=False)
    user_author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    comment_author = relationship("User", back_populates="comments")
    blog_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


db.create_all()


@app.route('/')
def get_all_posts():
    admin = current_user.get_id()
    is_admin = False
    if admin is not None:
        admin = int(admin)
        if admin == 1:
            is_admin = True
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated, is_admin=is_admin)


@app.route('/register', methods=["POST", "GET"])
def register():
    form = CreateRegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        if User.query.filter_by(email=email).first() is None:
            password = form.password.data
            name = form.name.data
            password = generate_password_hash(password=password, method="pbkdf2:sha256", salt_length=8)
            new_user = User(
                email=email,
                password=password,
                name=name
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for("get_all_posts"))
        else:
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for("login"))
    else:
        return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=["POST", "GET"])
def login():
    form = CreateLoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user_db = User.query.filter_by(email=email).first()
        if user_db:
            user_pass = user_db.password
            if check_password_hash(password=password, pwhash=user_pass):
                login_user(user_db)
                return redirect(url_for("get_all_posts"))
            else:
                flash("Incorrect Password")
                return redirect(url_for("login"))
        else:
            flash("The email does not exist, please try again.")
            return redirect(url_for("login"))
    else:
        return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    comment_form = CreateCommentForm()
    if comment_form.validate_on_submit():
        if current_user.is_authenticated:
            comment = comment_form.comment.data
            blog = BlogPost.query.get(post_id)
            new_comment = Comment(
                test=comment,
                user_author_id=current_user.id,
                blog_id=blog.id
            )
            db.session.add(new_comment)
            db.session.commit()

            return redirect(url_for("show_post", post_id=post_id))
        else:
            flash("You need to log in or register to comment")
            return redirect(url_for("login"))
    else:
        requested_post = BlogPost.query.get(post_id)
        admin = current_user.get_id()
        is_admin = False
        if admin is not None:
            admin = int(admin)
            if admin == 1:
                is_admin = True
        comments = Comment.query.filter_by(blog_id=post_id).all()
        return render_template("post.html", post=requested_post,
                               form=comment_form,
                               logged_in=current_user.is_authenticated, is_admin=is_admin, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=["GET", "POST"])
@decorator_admin
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            user_author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>")
@decorator_admin
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        user_author_id=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@decorator_admin
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts', logged_in=current_user.is_authenticated))


if __name__ == "__main__":
    app.run()
