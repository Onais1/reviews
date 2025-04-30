import os
from flask import Flask, render_template, request, redirect, url_for, flash, Response, send_file, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo
import csv
from io import StringIO
from textblob import TextBlob
import xlwt
import io
from datetime import datetime
from flask_migrate import Migrate

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'Onais#£786')

# Ensure the instance directory exists
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, 'instance')
os.makedirs(INSTANCE_DIR, exist_ok=True)  # Create instance directory if it doesn't exist
DB_PATH = os.path.join(INSTANCE_DIR, 'reviews.db').replace('\\', '/')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'user_login'

migrate = Migrate(app, db)

# Association table for likes and dislikes
likes_dislikes = db.Table('likes_dislikes',
    db.Column('user_id', db.Integer, db.ForeignKey('regular_user.id'), primary_key=True),
    db.Column('review_id', db.Integer, db.ForeignKey('review.id'), primary_key=True),
    db.Column('is_like', db.Boolean, nullable=False)
)

# Admin model
class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Increased length for hashed passwords
    is_admin = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

# Regular User model
class RegularUser(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Increased length for hashed passwords
    reviews = db.relationship('Review', backref='user', lazy=True)
    interactions = db.relationship('Review', secondary=likes_dislikes, backref='user_interacted', lazy=True)

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

# Review model
class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstName = db.Column(db.String(80), nullable=False)
    lastName = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    review = db.Column(db.Text, nullable=False)
    likes = db.Column(db.Integer, default=0)
    dislikes = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('regular_user.id'), nullable=False)
    sentiment = db.Column(db.String(20), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<Review {self.firstName}>'

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Sign Up')

class ReviewForm(FlaskForm):
    firstName = StringField('First Name', validators=[DataRequired()])
    lastName = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    review = TextAreaField('Review', validators=[DataRequired()])
    submit = SubmitField('Submit')

class LikeDislikeForm(FlaskForm):
    submit = SubmitField('')

class DeleteReviewForm(FlaskForm):
    submit = SubmitField('Delete')

# Load user for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    user_type = session.get('user_type')
    print(f"Loading user with ID: {user_id}, Type: {user_type}")
    if user_type == 'admin':
        return Admin.query.get(int(user_id))
    return RegularUser.query.get(int(user_id))

# Sentiment analysis
def classify_data(feedback):
    blob = TextBlob(feedback)
    polarity = blob.sentiment.polarity
    print(f"Feedback: {feedback}, Polarity: {polarity}")

    POSITIVE_THRESHOLD = 0.5  # Increased to require stronger positive sentiment
    NEGATIVE_THRESHOLD = -0.5  # Increased to require stronger negative sentiment
    BORDERLINE_POSITIVE = 0.1  # Lower threshold for borderline positive
    BORDERLINE_NEGATIVE = -0.1  # Lower threshold for borderline negative

    # Expanded mixed keywords and phrases
    mixed_keywords = [
        "okay", "alright", "fine", "not bad", "nothing special", "could be better",
        "average", "so-so", "decent", "not great", "some issues", "but", "however",
        "mixed", "on the other hand"
    ]
    negative_indicators = ["not", "issues", "problem", "bad", "poor", "lacking"]

    # Check for mixed sentiment: presence of mixed keywords or a combination of positive and negative/neutral
    feedback_lower = feedback.lower()
    has_mixed_keywords = any(keyword in feedback_lower for keyword in mixed_keywords)
    has_negative_indicators = any(indicator in feedback_lower for indicator in negative_indicators)

    # Check for mixed sentiment: presence of mixed keywords or a combination of positive and negative/neutral
    if (has_mixed_keywords or
        (BORDERLINE_POSITIVE <= polarity <= POSITIVE_THRESHOLD and has_negative_indicators) or 
        (NEGATIVE_THRESHOLD <= polarity <= BORDERLINE_NEGATIVE and any("good" in feedback_lower or "great" in feedback_lower))):
        return "Mixed"

    # Polarity-based classification
    if polarity > POSITIVE_THRESHOLD:
        return "Positive"
    elif polarity < NEGATIVE_THRESHOLD:
        return "Negative"
    else:
        return "Neutral"

# Routes
@app.route("/")
def home():
    form = ReviewForm()
    return render_template('home.html', form=form)

@app.route("/update_reviews_timestamps")
def update_reviews_timestamps():
    with app.app_context():
        reviews = Review.query.filter(Review.created_at.is_(None)).all()
        for review in reviews:
            review.created_at = datetime.utcnow()
        db.session.commit()
        return "Reviews updated successfully!", 200

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated and isinstance(current_user, Admin):
        return redirect(url_for('admin'))
    form = SignupForm()
    if form.validate_on_submit():
        # Check if username already exists
        existing_admin = Admin.query.filter_by(username=form.username.data).first()
        if existing_admin:
            flash('Username already exists. Please choose a different username.', 'danger')
            return redirect(url_for('signup'))
        
        # Proceed with admin creation if username is unique
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        print(f"Created admin object: {form.username.data}, hashed password: {hashed_password}")
        admin = Admin(username=form.username.data, password=hashed_password, is_admin=True)
        try:
            db.session.add(admin)
            print("Admin added to session.")
            db.session.commit()
            flash('Admin account created successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            print(f"Error saving admin to database: {str(e)}")
            flash('An error occurred while creating your admin account. Please try again.', 'danger')
            return redirect(url_for('signup'))
    return render_template('signup.html', form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated and isinstance(current_user, Admin):
        return redirect(url_for('admin'))
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        user = Admin.query.filter_by(username=username).first()
        print(f"Found user: {user}")
        if user:
            print(f"Password check: {user.check_password(form.password.data)}")
        if user and user.check_password(form.password.data):
            session['user_type'] = 'admin'  # Store user type in session
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for('admin'))
        flash("Login failed! Check your username and/or password.", "danger")
    return render_template('login.html', form=form)

@app.route("/logout")
def logout():
    session.pop('user_type', None)  # Clear user type from session
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for('newswire'))

@app.route("/admin")
@login_required
def admin():
    if not isinstance(current_user, Admin):
        flash("You do not have permission to access this page.", "danger")
        return redirect(url_for('newswire'))
    reviews = Review.query.all()
    delete_form = DeleteReviewForm()
    return render_template("admin.html", reviews=reviews, delete_form=delete_form)

@app.route("/review/<int:review_id>")
@login_required
def review_details(review_id):
    review = Review.query.get_or_404(review_id)
    return render_template("review_details.html", review=review)

@app.route("/delete_review/<int:review_id>", methods=["POST"])
@login_required
def delete_review(review_id):
    if not isinstance(current_user, Admin):
        flash("You do not have permission to delete this review.", "danger")
        return redirect(url_for('newswire'))
    form = DeleteReviewForm()
    if form.validate_on_submit():
        try:
            review = Review.query.get_or_404(review_id)
            db.session.delete(review)
            db.session.commit()
            flash("Review deleted successfully!", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Error deleting review: {str(e)}", "danger")
    return redirect(url_for('admin'))

@app.route("/submit", methods=["POST"])
@login_required
def submit():
    if isinstance(current_user, Admin):
        flash("Admins cannot submit reviews.", "danger")
        return redirect(url_for('admin'))
    form = ReviewForm()
    if form.validate_on_submit():
        try:
            sentiment = classify_data(form.review.data)
            new_review = Review(
                firstName=form.firstName.data,
                lastName=form.lastName.data,
                email=form.email.data,
                review=form.review.data,
                sentiment=sentiment,
                user_id=current_user.id
            )
            db.session.add(new_review)
            db.session.commit()
            return render_template("thanks.html", review=new_review)
        except Exception as e:
            db.session.rollback()
            flash(f"Error submitting review: {str(e)}", "danger")
            return redirect(url_for('newswire'))
    flash("Invalid form data.", "danger")
    return redirect(url_for('newswire'))

@app.route('/download/csv')
@login_required
def download_csv():
    if not isinstance(current_user, Admin):
        flash("You do not have permission to access this.", "danger")
        return redirect(url_for('newswire'))
    reviews = Review.query.all()
    if not reviews:
        flash("No reviews available to download.", "info")
        return redirect(url_for('admin'))
    output = StringIO()
    writer = csv.writer(output, lineterminator='\n')
    writer.writerow(["id", "first_name", "last_name", "email", "review", "sentiment", "date"])
    for review in reviews:
        created_at = review.created_at.strftime('%m/%d/%Y') if review.created_at else 'N/A'
        writer.writerow([review.id, review.firstName, review.lastName, review.email, review.review, review.sentiment or 'N/A', created_at])
    # Encode the CSV content as UTF-8 with BOM to ensure Excel compatibility
    csv_data = output.getvalue()
    output.close()
    return Response(
        '\ufeff' + csv_data,  # Add UTF-8 BOM
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=reviews.csv"}
    )

@app.route('/download/xls')
@login_required
def download_xls():
    if not isinstance(current_user, Admin):
        flash("You do not have permission to access this.", "danger")
        return redirect(url_for('newswire'))
    reviews = Review.query.all()
    if not reviews:
        flash("No reviews available to download.", "info")
        return redirect(url_for('admin'))
    try:
        wb = xlwt.Workbook()
        ws = wb.add_sheet("Reviews")
        headers = ["ID", "First Name", "Last Name", "Email", "Review", "Sentiment", "Date"]
        for col, header in enumerate(headers):
            ws.write(0, col, header)
        for row, review in enumerate(reviews, start=1):
            created_at = review.created_at.strftime('%m/%d/%Y') if review.created_at else 'N/A'
            ws.write(row, 0, review.id)
            ws.write(row, 1, review.firstName)
            ws.write(row, 2, review.lastName)
            ws.write(row, 3, review.email)
            ws.write(row, 4, review.review)
            ws.write(row, 5, review.sentiment or 'N/A')
            ws.write(row, 6, created_at)
        file_stream = io.BytesIO()
        wb.save(file_stream)
        file_stream.seek(0)
        return send_file(
            file_stream,
            download_name="reviews.xls",
            as_attachment=True,
            mimetype="application/vnd.ms-excel"
        )
    except Exception as e:
        flash(f"Error generating XLS file: {str(e)}", "danger")
        return redirect(url_for('admin'))
    
# User signup and login routes 
@app.route("/user_signup", methods=["GET", "POST"]) # User signup route
def user_signup(): # User signup function
    form = SignupForm() # Create a signup form instance
    if form.validate_on_submit(): # Check if the form is submitted and valid
        # Check if username already exists
        existing_user = RegularUser.query.filter_by(username=form.username.data).first() # Check if the username already exists in the database
        if existing_user:
            flash('Username already exists. Please choose a different username.', 'danger')
            return redirect(url_for('user_signup')) # If the username exists, flash a message and redirect to the signup page
        
        # Proceed with user creation if username is unique
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        print(f"Created user object: {form.username.data}, hashed password: {hashed_password}")
        user = RegularUser(username=form.username.data, password=hashed_password)
        try:
            db.session.add(user)
            print("User added to session.") # Add the user to the session
            db.session.commit()
            flash('Account created successfully! You can now log in.', 'success') # Flash a success message
            return redirect(url_for('user_login'))
        except Exception as e:
            db.session.rollback()
            print(f"Error saving user to database: {str(e)}") # Rollback the session in case of an error
            flash('An error occurred while creating your account. Please try again.', 'danger')
            return redirect(url_for('user_signup'))
    return render_template('user_signup.html', form=form) # Render the signup form

@app.route("/user_login", methods=["GET", "POST"])
def user_login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        user = RegularUser.query.filter_by(username=username).first()
        print(f"Found user: {user}")
        if user:
            print(f"Password check: {user.check_password(form.password.data)}")
        if user and user.check_password(form.password.data):
            session['user_type'] = 'regular'  # Store user type in session
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for('newswire'))
        flash("Login failed! Check your username and/or password.", "danger")
    return render_template('user_login.html', form=form)

@app.route("/user_logout")
@login_required
def user_logout():
    session.pop('user_type', None)  # Clear user type from session
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for('newswire'))

@app.route("/newswire")
def newswire():
    reviews = Review.query.all()
    like_form = LikeDislikeForm()
    dislike_form = LikeDislikeForm()
    return render_template("newswire.html", reviews=reviews, like_form=like_form, dislike_form=dislike_form)

@app.route("/likes/<int:review_id>", methods=["POST"])
@login_required
def like_review(review_id):
    if isinstance(current_user, Admin):
        flash("Admins cannot like reviews.", "danger")
        return redirect(url_for('admin'))
    form = LikeDislikeForm()
    if form.validate_on_submit():
        review = Review.query.get_or_404(review_id)
        existing_dislike = db.session.query(likes_dislikes).filter_by(user_id=current_user.id, review_id=review_id, is_like=False).first()
        if existing_dislike:
            flash("You have already disliked this review. Remove your dislike to like it.", "info")
            return redirect(url_for('newswire'))
        if not db.session.query(likes_dislikes).filter_by(user_id=current_user.id, review_id=review_id, is_like=True).first():
            review.likes += 1
            db.session.execute(likes_dislikes.insert().values(user_id=current_user.id, review_id=review_id, is_like=True))
            db.session.commit()
            flash("You liked this review.", "success")
        else:
            flash("You have already liked this review.", "info")
    return redirect(url_for('newswire'))

@app.route("/dislikes/<int:review_id>", methods=["POST"])
@login_required
def dislike_review(review_id):
    if isinstance(current_user, Admin):
        flash("Admins cannot dislike reviews.", "danger")
        return redirect(url_for('admin'))
    form = LikeDislikeForm()
    if form.validate_on_submit():
        review = Review.query.get_or_404(review_id)
        existing_like = db.session.query(likes_dislikes).filter_by(user_id=current_user.id, review_id=review_id, is_like=True).first()
        if existing_like:
            flash("You have already liked this review. Remove your like to dislike it.", "info")
            return redirect(url_for('newswire'))
        if not db.session.query(likes_dislikes).filter_by(user_id=current_user.id, review_id=review_id, is_like=False).first():
            review.dislikes += 1
            db.session.execute(likes_dislikes.insert().values(user_id=current_user.id, review_id=review_id, is_like=False))
            db.session.commit()
            flash("You disliked this review.", "success")
        else:
            flash("You have already disliked this review.", "info")
    return redirect(url_for('newswire'))

if __name__ == "__main__":
    app.run(debug=True)
