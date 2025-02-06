from flask import Flask, render_template, request, redirect, url_for, flash, Response, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import csv
from openpyxl import Workbook
import io
from datetime import datetime
from flask_migrate import Migrate


app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'Onais#£786'  
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///reviews.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  

migrate = Migrate(app, db)

# User model (for admins)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Review model (for storing reviews)
class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(80), nullable=False)
    lastName = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    review = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Review {self.firstName}>'

# Load_user function for login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
def home():
    # Render the home page (home.html) as the default page
    return render_template("home.html")

@app.route("/update_reviews_timestamps")
def update_reviews_timestamps():
    # Update reviews without a created_at value
    with app.app_context():
        reviews = Review.query.filter(Review.created_at.is_(None)).all()
        for review in reviews:
            review.created_at = datetime.utcnow()
        db.session.commit()
        return "Reviews updated successfully!", 200

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('signup'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        user = User.query.filter_by(username=username).first()
        if user:
            flash("Username already exists!", "danger")
            return redirect(url_for('signup'))

        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for('admin'))

        flash("Login failed! Check your username and/or password.", "danger")

    return render_template('login.html')

@app.route("/logout")
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route("/admin")
@login_required  
def admin():
    reviews = Review.query.all()
    return render_template("admin.html", reviews=reviews)

@app.route("/review/<int:review_id>")
@login_required
def review_details(review_id):
    review = Review.query.get_or_404(review_id)
    return render_template("review_details.html", review=review)

@app.route("/submit", methods=["POST"])
def submit():
    firstName = request.form['firstName']
    lastName = request.form['lastName']
    email = request.form['email']
    review = request.form['review']

    new_review = Review(firstName=firstName, lastName=lastName, email=email, review=review)
    db.session.add(new_review)
    db.session.commit()

    return render_template("thanks.html")  # Render the thank you page with the styled template


@app.route('/download/csv')
@login_required
def download_csv():
    reviews = Review.query.all()
    output = "id, first_name, last_name, email, review, date\n"
    
    for review in reviews:
        created_at = review.created_at.strftime('%Y-%m-%d') if review.created_at else 'N/A'
        output += f"{review.id}, {review.firstName}, {review.lastName}, {review.email}, {review.review.replace(',', ' ')}, {created_at}\n"

    return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=reviews.csv"})

@app.route('/download/xls')
@login_required
def download_xls():
    reviews = Review.query.all()

    wb = Workbook()
    ws = wb.active
    ws.append(["ID", "First Name", "Last Name", "Email", "Review", "Date"])

    for review in reviews:
        created_at = review.created_at.strftime('%Y-%m-%d') if review.created_at else 'N/A'
        ws.append([review.id, review.firstName, review.lastName, review.email, review.review, created_at])

    file_stream = io.BytesIO()
    wb.save(file_stream)
    file_stream.seek(0)

    return send_file(file_stream, download_name="reviews.xlsx", as_attachment=True)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Ensure the database is created
    app.run(debug=True)
