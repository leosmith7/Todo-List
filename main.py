from flask import Flask, jsonify, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
app.config['SECRET_KEY'] = 'your_secret_key'  # Set a secret key for session management
db = SQLAlchemy(app)
login_manager = LoginManager(app)

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    task = db.Column(db.String(255), nullable=False)
    due_date = db.Column(db.DateTime, nullable=False)
    completed = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == 'POST':
        if 'login' in request.form:
            # Handle login
            email = request.form['loginEmail']
            password = request.form['loginPassword']
            user = User.query.filter_by(email=email).first()
            if user and check_password_hash(user.password, password):
                login_user(user)
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Login failed. Check your email and password.', 'danger')

        elif 'register' in request.form:
            # Handle registration
            username = request.form['registerName']
            email = request.form['registerEmail']
            password = request.form['registerPassword']
            confirm_password = request.form['registerConfirmPassword']

            if password != confirm_password:
                flash('Passwords do not match!', 'danger')
                return redirect(url_for('home'))

            if User.query.filter_by(email=email).first() or User.query.filter_by(username=username).first():
                flash('Email or username already exists!', 'danger')
                return redirect(url_for('home'))

            new_user = User(username=username, email=email, password=generate_password_hash(password))
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('home'))

    return render_template("login.html")

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    if request.method == 'POST':
        task_description = request.form['task']
        due_date = request.form['due_date']
        new_task = Task(user_id=current_user.id, task=task_description, due_date=datetime.strptime(due_date, '%Y-%m-%d'))
        db.session.add(new_task)
        db.session.commit()
        flash('Task added successfully!', 'success')
        return redirect(url_for('dashboard'))

    tasks = Task.query.filter_by(user_id=current_user.id).all()
    return render_template("dashboard.html", tasks=tasks)

@app.route("/complete_task/<int:task_id>")
@login_required
def complete_task(task_id):
    task = Task.query.get_or_404(task_id)
    task.completed = not task.completed
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route("/delete_task/<int:task_id>")
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    db.session.delete(task)
    db.session.commit()
    flash('Task deleted successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
