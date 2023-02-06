from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash,check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint("auth",__name__)



@auth.route("/sign-up", methods=["GET","POST"])
def sign_up():

    if request.method == "POST":
        email = request.form.get("email")
        username = request.form.get("username")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")

        user = User.query.filter_by(email=email).first()
        if user:
            if user.email == email:
                flash("Email already used", category="error")
            else:
                flash("Username already taken", category="error")

        elif len(email) < 4:
            flash("Email must be greater than 4 characters", category="error")
          

        elif len(username) < 2:
            flash("Username must be greater than 2 characters", category="error")

    
        elif len(password1) < 4 or password1 != password2:
            flash("Password must be greater than 4 characters", category="error")
            
        
        elif password1 != password2:
            flash("Passwords do not match", category="error")

        

        else:
            new_user = User(email=email,username=username,password=generate_password_hash(password1, method="sha256"))
            db.session.add(new_user)
            db.session.commit()
            login_user(user, remember=True)

            flash("Success!", category="success")
            return redirect(url_for("views.home")) #could use / but views.home guarentees even after changing home dir



    return render_template("sign_up.html", user=current_user)

@auth.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()
        if user:
            if check_password_hash(user.password,password):
                flash("Logged in successfully", category="success")
                login_user(user, remember=True)
                return redirect(url_for("views.home"))

            else:
                flash("Incorrect username or password", category="error")
        else:
            flash("Incorrect username", category="error")

            

    return render_template("login.html", user=current_user)

@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))

 