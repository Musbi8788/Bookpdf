from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

import os

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get("Secret_Key")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["DEBUG"] = True
db = SQLAlchemy(app)

# config login manager
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB.
# with app.app_context():
#     db.create_all()


@app.route('/')
def home():
    # Every render_template has a logged_in variable set.
    return render_template("index.html", logged_in=current_user.is_authenticated)

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/donate")
def donate():
    return render_template("donate.html")

@app.route('/register',methods=["POST","GET"])
def register():
    if request.method == "POST":

        if User.query.filter_by(email=request.form.get("email")).first():
            # User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        # hashed a strong password for your users
        hashed_password = generate_password_hash(
            request.form.get("password") or "",
            method='pbkdf2:sha256',
            salt_length=8)
        new_user = User (
            email = request.form.get("email"),
            name = request.form.get("name"),
            password = hashed_password
        )
        db.session.add(new_user)
        db.session.commit()

        # Log in and authenticate user after adding details to database.
        login_user(new_user)

        return redirect( url_for("home",name=new_user.name))

    return render_template("register.html",logged_in=current_user.is_authenticated)


@app.route('/login',methods=["POST","GET"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password") or ""


        #Find user by email entered.
        user = User.query.filter_by(email=email).first()
        print(user)

        # Check if the user email Doesn't exist
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for("login"))


        # incorrect password for the user
        elif not check_password_hash(user.password, password):
            flash("Password incorrect, please try again.")
            return redirect(url_for("login"))

        #Email exists and password correct
        else:
            login_user(user)
            return redirect(url_for("home"))

    return render_template("login.html",logged_in=current_user.is_authenticated)


# @app.route('/secrets')
# @login_required
# def secrets():
#     print(current_user.name)
#     # user is Accepted.
#     return render_template("secrets.html", name=current_user.name, logged_in=True)
#
# @app.route('/logout')
# def logout():
#     logout_user()
#     return redirect(url_for("home"))
#
#
# @app.route('/download')
# def download():
#     return send_from_directory( 'static', filename="files/cheat_sheet.pdf")

#

if __name__ == "__main__":
    app.run(debug=True)
