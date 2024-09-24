from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps  # Import this to create a login_required decorator

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Needed for session management

# Configure SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Create a User model for the database
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            # Redirect to login page if not logged in
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Route for the main to-do list page (protected)
@app.route('/')
@login_required
def index():
    return render_template('index.html')

# Route for the login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        # Check if the user exists and the password is correct
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password')

    return render_template('login.html')

# Route for the register page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        # Create a hashed password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Create a new user and add to the database
        new_user = User(name=name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # Redirect to login after registration
        return redirect(url_for('login'))
    return render_template('register.html')

# Route for creating a new list (protected)
@app.route('/new-list')
@login_required
def new_list():
    return render_template('index.html')

# Route for saving the list (protected)
@app.route('/save-list', methods=['POST'])
@login_required
def save_list():
    return redirect(url_for('index'))

# Route for logging out the user
@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Clear session
    flash('You have been logged out successfully.')
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)
