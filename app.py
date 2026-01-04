from openai import OpenAI
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timezone
import json
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
import os

# Create the app and configure it
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "1234567890abcdef")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///smartaid.db'

# Folder to store uploaded files
UPLOAD_FOLDER = os.path.join('static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    profile_pic = db.Column(db.String(200), default='default.png')

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    data = db.Column(db.LargeBinary, nullable=False)  # Store file content
    mimetype = db.Column(db.String(50), nullable=False)  # Store file type
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='documents')

class Reminder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    datetime = db.Column(db.DateTime, nullable=False)
    notified = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='reminders')
    created_at = db.Column(db.DateTime, default=lambda:datetime.now(timezone.utc))

class PushSubscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subscription_json = db.Column(db.Text, nullable=False)
    user = db.relationship('User', backref='push_subscriptions')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# OpenAI client setup
load_dotenv()
client = OpenAI( 
    api_key= os.getenv("OPENAI_API_KEY")
)
MODEL_NAME = "gpt-4o-mini"


# === Routes ===
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/location")
def location():
    return render_template("location.html")

@app.route("/demo")
def demo():
    return render_template("demo.html")

@app.route("/reminder")
def reminder():
    return render_template("reminder.html")


@app.route('/registration', methods=['GET', 'POST'])
def registration():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        phone = request.form['phone']
        age = request.form['age']
        gender = request.form['gender']
        password = request.form['password']
        confirm = request.form['confirm_password']

        if password != confirm:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('registration'))

        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "warning")
            return redirect(url_for('registration'))

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(first_name=first_name, last_name=last_name, email=email,
                        phone=phone, age=age, gender=gender, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))
    return render_template('registration.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user) # Use Flask-Login's login_user function
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    user_files = current_user.documents  # List of Document objects
    return render_template('dashboard.html', user=current_user, files=user_files)

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        flash('No file part', 'warning')
        return redirect(url_for('dashboard'))

    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'warning')
        return redirect(url_for('dashboard'))

    filename = secure_filename(file.filename)
    new_file = Document(
        filename=filename,
        data=file.read(),
        mimetype=file.content_type,
        user_id=current_user.id
    )
    db.session.add(new_file)
    db.session.commit()
    flash('File uploaded successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/uploads/<int:file_id>')
@login_required
def uploaded_file(file_id):
    file = Document.query.get_or_404(file_id)
    return (file.data, 200, {
        'Content-Type': file.mimetype,
        'Content-Disposition': f'inline; filename={file.filename}'
    })

@app.route('/delete_file/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file = Document.query.get_or_404(file_id)

    # Ensure the current user owns this file
    if file.user_id != current_user.id:
        flash("You are not authorized to delete this file.", "danger")
        return redirect(url_for('dashboard'))

    db.session.delete(file)
    db.session.commit()
    flash(f"File '{file.filename}' deleted successfully!", "success")
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required # Protect this route
def logout():
    logout_user() # Use Flask-Login's logout_user function
    flash('Logged out successfully!', 'info')
    return redirect(url_for('home'))

@app.route('/api/reminders', methods=['GET'])
@login_required
def get_reminders():
    reminders = Reminder.query.filter_by(user_id=current_user.id).order_by(Reminder.datetime).all()
    return jsonify([{
        'id': r.id,
        'title': r.title,
        'datetime': r.datetime.isoformat(),
        'notified': r.notified
    } for r in reminders])

@app.route('/api/reminders', methods=['POST'])
@login_required
def add_reminder():
    data = request.json
    reminder = Reminder(
        title=data['title'],
        datetime=datetime.fromisoformat(data['datetime']),
        user_id=current_user.id
    )
    db.session.add(reminder)
    db.session.commit()
    return jsonify({'id': reminder.id, 'message': 'Reminder created'}), 201

@app.route('/api/reminders/<int:reminder_id>', methods=['DELETE'])
@login_required
def delete_reminder(reminder_id):
    reminder = Reminder.query.get_or_404(reminder_id)
    if reminder.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    db.session.delete(reminder)
    db.session.commit()
    return jsonify({'message': 'Reminder deleted'}), 200

@app.route('/api/push-subscription', methods=['POST'])
@login_required
def save_push_subscription():
    subscription_json = request.json
    
    # Delete old subscriptions for this user
    PushSubscription.query.filter_by(user_id=current_user.id).delete()
    
    # Save new subscription
    subscription = PushSubscription(
        user_id=current_user.id,
        subscription_json=json.dumps(subscription_json)
    )
    db.session.add(subscription)
    db.session.commit()
    return jsonify({'message': 'Subscription saved'}), 201

def check_reminders():
    with app.app_context():
        now = datetime.now()  # Changed from utcnow() to now()
        due_reminders = Reminder.query.filter(
            Reminder.datetime <= now,
            Reminder.notified == False
        ).all()
        
        for reminder in due_reminders:
            # Mark as notified
            reminder.notified = True
            db.session.commit()
            
            print(f"🔔 Reminder due: {reminder.title} for user {reminder.user_id}")

# Initialize scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(func=check_reminders, trigger="interval", seconds=30)
scheduler.start()

# Shut down the scheduler when exiting the app
import atexit
atexit.register(lambda: scheduler.shutdown())

@app.route("/chat", methods=['POST'])
def chat():
    user_message = request.json.get("message", "")

    if not user_message:
        return jsonify({"reply": "Please enter some symptoms or questions."})

    chat_prompt = f"""
    You are SmartAid, a medical-symptom analyzer chatbot. You analyze the user's messages in context — not just the latest message — 
    to detect possible health symptoms, conditions, or related personal details (like age, weight, gender, or lifestyle).

    If symptoms are mentioned, respond in this exact format (using newlines as shown):

    🔍 <Short title summarizing condition>
    🧠 Description: <Brief explanation (1–3 lines)>
    📊 Disease Possibility: <Likelihood assessment (1 line)>
    💪 health Guidance: <health improvements (2 lines)>
    🥗 Healthy Food Suggestions: <Food recommendations (2–4 items, comma-separated)>
    ⚠️ Severity: <Low, Medium, or High>
    Disclaimer: If symptoms are severe or worsen, seek medical attention.

    If the user provides information like age, weight, or health habits (not a symptom), use that information to give a relevant health insight or advice
    related to previous symptoms or general well-being. Be brief and practical.

    If the user is just greeting or chatting casually, respond in a warm, friendly tone (1–2 sentences).

    Important:
    - Respond only in plain text — no markdown, no JSON, no code blocks.
    - Keep the tone clear, short, and human-like.
    - Always include a one-line disclaimer at the end of symptom responses.

    The user says: "{user_message}"
    """

    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": "You are Smart-Aid, a helpful medical assistant."},
                {"role": "user", "content": chat_prompt}
            ],
            max_tokens=400,
            temperature=0.7
        )
        reply_text = response.choices[0].message.content.strip()
    except Exception as e:
        print("❌ OpenAI API Error:", e)
        reply_text = "Sorry, something went wrong. Please try again."

    return jsonify({"reply": reply_text})

if __name__ == "__main__":
    # Create database tables BEFORE running the app
    with app.app_context():
        db.create_all()
        print("✅ Database tables created successfully!")
    
    # Run the app
    from os import environ
    port = int(environ.get('PORT', 5000))

    app.run(host='0.0.0.0', port=port, debug=True)
