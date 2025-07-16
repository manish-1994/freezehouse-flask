from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask_mail import Mail, Message
from flask_migrate import Migrate
from flask_dance.contrib.google import make_google_blueprint, google
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import requests
import random
import os
from config import Config
import logging


# Allow OAuth over HTTP (for development only!)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# ======================
# App Initialization
# ======================
app = Flask(__name__)
app.config.from_object(Config)

# 🔐 PostgreSQL reconnect & stability settings
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,   # ensures connection is alive
    'pool_recycle': 280      # recycle after 280 seconds (~5 minutes)
}

db = SQLAlchemy(app)
mail = Mail(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# ========== Telegram Setup ==========
BOT_TOKEN = app.config['TELEGRAM_BOT_TOKEN']
ADMIN_CHAT_IDS = app.config['TELEGRAM_CHAT_IDS']

# ========== Google OAuth ==========
google_bp = make_google_blueprint(
    client_id=os.getenv("GOOGLE_OAUTH_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email"
    ],
    redirect_to="google_login"  # This should point to your route that handles Google login
)

app.register_blueprint(google_bp, url_prefix="/login")

# ========== Models ==========
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    username = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    aadhar = db.Column(db.String(20), nullable=True)
    dob = db.Column(db.String(20), nullable=True)
    password = db.Column(db.String(255), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)

class OTPStore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)
    otp = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class BathType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    price = db.Column(db.Float, nullable=False)

class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    date = db.Column(db.String(100))
    time = db.Column(db.String(100))
    reason = db.Column(db.String(250))
    bath_type = db.Column(db.String(100))
    price = db.Column(db.Float)

class Pricing(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)

class Benefit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ========== Helpers ==========
# Rename this helper to match usage across your app
def notify_admins(message):
    token = os.getenv('TELEGRAM_BOT_TOKEN')
    chat_ids = os.getenv('TELEGRAM_CHAT_IDS').split(',')
    for chat_id in chat_ids:
        try:
            res = requests.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                data={"chat_id": chat_id.strip(), "text": message},
                timeout=5
            )
        except Exception as e:
            print(f"Telegram notify error: {e}")


@app.route("/test-telegram")
def test_telegram():
    message = "✅ Test message from Freezehouse Telegram bot!"
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")

    if not token or not chat_id:
        error_msg = "❌ TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is missing"
        app.logger.error(error_msg)
        return error_msg, 500

    try:
        response = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data={"chat_id": chat_id, "text": message},
            timeout=5
        )
        app.logger.info(f"Telegram response: {response.status_code} - {response.text}")
        return f"✅ Sent! Status: {response.status_code}, Response: {response.text}"
    except Exception as e:
        app.logger.exception("Telegram send failed")
        return f"❌ Error: {str(e)}", 500



# ========== Google Login ==========
@app.route("/google-login")
def google_login():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Failed to fetch user info from Google.", "danger")
        return redirect(url_for("login"))

    info = resp.json()
    email = info.get("email")
    name = info.get("name", "Google User")

    if not email:
        flash("No email received from Google.", "danger")
        return redirect(url_for("login"))

    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(username=name, email=email, password=generate_password_hash("google"), is_admin=(email == "admin@freezehouse.com"))
        db.session.add(user)
        db.session.commit()

    login_user(user)
    session['user_id'] = user.id
    session['username'] = user.username
    session['is_admin'] = user.is_admin

    flash("Logged in with Google!", "success")
    return redirect(url_for('dashboard' if not user.is_admin else 'admin'))

# CONTINUES BELOW ⬇️
# ========== Auth & Registration ==========
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        phone = request.form['phone']
        aadhar = request.form['aadhar']
        dob = request.form['dob']
        password = generate_password_hash(request.form['password'])

        if User.query.filter((User.email == email) | (User.phone == phone)).first():
            flash("User already exists.")
            return redirect(url_for('register'))

        is_admin = email == 'admin@freezehouse.com'
        user = User(username=username, email=email, phone=phone, aadhar=aadhar, dob=dob, password=password, is_admin=is_admin)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful.")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            flash("Login successful!")
            return redirect(url_for('dashboard' if not user.is_admin else 'admin'))
        flash("Invalid credentials.")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('home'))

# ========== Password Reset ==========
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            otp = str(random.randint(100000, 999999))
            db.session.add(OTPStore(email=email, otp=otp))
            db.session.commit()
            msg = Message("Freezehouse OTP", sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f"Your OTP is: {otp}"
            mail.send(msg)
            session['reset_email'] = email
            flash("OTP sent to your email.")
            return redirect(url_for('verify_otp'))
        flash("No user found with that email.")
    return render_template('forgot_password.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        otp = request.form['otp']
        email = session.get('reset_email')
        record = OTPStore.query.filter_by(email=email, otp=otp).first()
        if record:
            db.session.delete(record)
            db.session.commit()
            return redirect(url_for('reset_password'))
        flash("Invalid OTP.")
    return render_template('verify_otp.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = session.get('reset_email')
        user = User.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(request.form['password'])
            db.session.commit()
            session.pop('reset_email', None)
            flash("Password reset successful.")
            return redirect(url_for('login'))
    return render_template('reset_password.html')

# ========== General Pages ==========
@app.route('/')
def home(): return render_template('index.html')

@app.route('/about')
def about(): return render_template('about.html')

@app.route('/services')
def services(): return render_template('services.html')

@app.route('/benefits')
def benefits(): return render_template('benefits.html', benefits=Benefit.query.all())

@app.route('/pricing')
def pricing(): return render_template('pricing.html', items=Pricing.query.all())

@app.route('/contact')
def contact(): return render_template('contact.html')

# ========== Dashboard & Booking ==========
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    bath_types = BathType.query.all()
    appointments = Appointment.query.filter_by(user_id=current_user.id).all()
    booked_slots = [(a.date, a.time) for a in Appointment.query.all()]

    if request.method == 'POST':
        date = request.form['date']
        time = request.form['time']
        reason = request.form['reason']
        bath_type = request.form['bath_type']
        bath = BathType.query.filter_by(name=bath_type).first()
        price = bath.price if bath else 0

        if Appointment.query.filter_by(date=date, time=time).first():
            flash("Slot already booked.")
            return redirect(url_for('dashboard'))

        appt = Appointment(user_id=current_user.id, date=date, time=time, reason=reason, bath_type=bath_type, price=price)
        db.session.add(appt)
        db.session.commit()

        notify_admins(f"""📅 New Appointment:
👤 Name: {current_user.username}
📞 Phone: {current_user.phone}
📧 Email: {current_user.email}
🛁 Bath Type: {bath_type}
💸 Price: ₹{price}
🕒 Date/Time: {date} {time}
📝 Reason: {reason}""")
        return redirect(url_for('dashboard'))

    return render_template('dashboard.html', appointments=appointments, bath_types=bath_types, booked_slots=booked_slots)

# ========== WhatsApp Booking ==========
@app.route('/whatsapp-booking', methods=['GET', 'POST'])
def whatsapp_booking():
    bath_types = BathType.query.all()
    if request.method == 'POST':
        name = request.form['name']
        phone = request.form['phone']
        date = request.form['date']
        time = request.form['time']
        reason = request.form['reason']
        bath_type = request.form['bath_type']

        user = User.query.filter_by(phone=phone).first()
        if not user:
            user = User(username=name, phone=phone, email=f"{phone}@example.com", password=generate_password_hash('default123'))
            db.session.add(user)
            db.session.commit()

        bath = BathType.query.filter_by(name=bath_type).first()
        price = bath.price if bath else 0

        appt = Appointment(user_id=user.id, date=date, time=time, reason=reason, bath_type=bath_type, price=price)
        db.session.add(appt)
        db.session.commit()

        notify_admins(f"""📲 WhatsApp Booking:
👤 Name: {name}
📞 Phone: {phone}
📧 Email: {user.email}
🛁 Bath Type: {bath_type}
💸 Price: ₹{price}
🕒 Date/Time: {date} {time}
📝 Reason: {reason}""")
        return "✅ WhatsApp Booking Confirmed"
    return render_template('whatsapp_booking.html', bath_types=bath_types)

# ========== Continue? ==========
# Next part: Admin panel, delete users, reschedule, init-db, etc.

# ========== Appointment Rescheduling ==========
@app.route('/reschedule/<int:id>', methods=['GET', 'POST'])
@login_required
def reschedule_appointment(id):
    appt = Appointment.query.get_or_404(id)
    if current_user.id != appt.user_id:
        flash("Unauthorized", "danger")
        return redirect(url_for('dashboard'))

    bath_types = BathType.query.all()
    if request.method == 'POST':
        appt.date = request.form['date']
        appt.time = request.form['time']
        appt.reason = request.form['reason']
        appt.bath_type = request.form['bath_type']
        bath = BathType.query.filter_by(name=appt.bath_type).first()
        appt.price = bath.price if bath else 0
        db.session.commit()

        notify_admins(f"""🔁 Appointment Rescheduled:
👤 Name: {current_user.username}
📞 Phone: {current_user.phone}
📧 Email: {current_user.email}
🛁 Bath Type: {appt.bath_type}
💸 Price: ₹{appt.price}
🕒 New Slot: {appt.date} {appt.time}
📝 Reason: {appt.reason}""")
        flash("Appointment rescheduled.")
        return redirect(url_for('dashboard'))

    return render_template('reschedule.html', appointment=appt, bath_types=bath_types)

@app.route('/delete/<int:id>')
@login_required
def delete_appointment(id):
    appt = Appointment.query.get_or_404(id)
    if appt.user_id == current_user.id:
        db.session.delete(appt)
        db.session.commit()
        flash("Appointment deleted.")
    return redirect(url_for('dashboard'))

# ========== Admin Dashboard ==========
@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        return redirect(url_for('login'))
    appointments = db.session.query(Appointment, User).join(User).all()
    return render_template('admin.html', appointments=appointments)

@app.route('/admin/delete/<int:id>')
@login_required
def admin_delete(id):
    if not current_user.is_admin:
        return redirect(url_for('login'))
    db.session.delete(Appointment.query.get_or_404(id))
    db.session.commit()
    flash("Appointment deleted by admin.")
    return redirect(url_for('admin'))

# ========== Admin User Management ==========
@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        flash("Access denied", "danger")
        return redirect(url_for('home'))

    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/delete-user/<int:id>')
@login_required
def delete_user(id):
    if not current_user.is_admin:
        flash("Access denied", "danger")
        return redirect(url_for('home'))

    user = User.query.get_or_404(id)
    notify_admins(f"""❌ User Deleted:
👤 Name: {user.username}
📧 Email: {user.email}
📞 Phone: {user.phone}
🆔 User ID: {user.id}""")
    db.session.delete(user)
    db.session.commit()
    flash("User deleted.")
    return redirect(url_for('admin_users'))

# ========== Bath Types ==========
@app.route('/admin/bath-types', methods=['GET', 'POST'])
@login_required
def manage_bath_types():
    if not current_user.is_admin:
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        price = float(request.form['price'])
        if not BathType.query.filter_by(name=name).first():
            db.session.add(BathType(name=name, price=price))
            db.session.commit()
        else:
            flash("Bath type already exists.")
    return render_template('manage_bath_types.html', bath_types=BathType.query.all())

@app.route('/delete_bath_type/<int:id>')
@login_required
def delete_bath_type(id):
    if not current_user.is_admin:
        return redirect(url_for('login'))
    db.session.delete(BathType.query.get_or_404(id))
    db.session.commit()
    flash('Bath type deleted.')
    return redirect(url_for('manage_bath_types'))

# ========== Pricing Management ==========
@app.route('/admin/pricing', methods=['GET', 'POST'])
@login_required
def manage_pricing():
    if not current_user.is_admin:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = float(request.form['price'])
        db.session.add(Pricing(title=title, description=description, price=price))
        db.session.commit()
        flash("✅ Pricing item added successfully!", "success")
        return redirect(url_for('manage_pricing'))

    pricing_items = Pricing.query.all()
    return render_template('manage_pricing.html', pricing_items=pricing_items)

@app.route('/admin/pricing/delete/<int:id>', methods=['GET'])
@login_required
def delete_pricing(id):
    if not current_user.is_admin:
        flash("Access denied", "danger")
        return redirect(url_for('admin'))

    item = Pricing.query.get_or_404(id)
    db.session.delete(item)
    db.session.commit()
    flash("✅ Pricing item deleted.", "success")
    return redirect(url_for('manage_pricing'))



# ========== Benefit Management ==========
@app.route('/admin/benefits', methods=['GET', 'POST'])
@login_required
def manage_benefits():
    if not current_user.is_admin:
        flash("Admin access only.", "warning")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        
        if title and description:
            new_benefit = Benefit(title=title, description=description)
            db.session.add(new_benefit)
            db.session.commit()
            flash("✅ Benefit added successfully!", "success")
        else:
            flash("❌ Both title and description are required.", "danger")

        return redirect(url_for('manage_benefits'))

    benefits = Benefit.query.all()
    return render_template('manage_benefits.html', benefits=benefits)

@app.route('/admin/benefits/delete/<int:id>', methods=['GET'])
@login_required
def delete_benefit(id):
    if not current_user.is_admin:
        flash("Admin access only.", "warning")
        return redirect(url_for('dashboard'))

    benefit = Benefit.query.get_or_404(id)
    db.session.delete(benefit)
    db.session.commit()
    flash("✅ Benefit deleted successfully.", "success")
    return redirect(url_for('manage_benefits'))

# ========== Utility ==========
@app.route('/init-db')
def init_db():
    db.create_all()
    return "✅ Database Initialized"

@app.route('/clear-session')
def clear_session():
    session.clear()
    flash("Session cleared.")
    return redirect(url_for('home'))

# ========== Run App ==========
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        admin_email = "admin@freezehouse.com"
        if not User.query.filter_by(email=admin_email).first():
            db.session.add(User(
                username="Admin",
                email=admin_email,
                phone="9999999999",
                aadhar="000000000000",
                dob="2000-01-01",
                password=generate_password_hash("admin"),
                is_admin=True
            ))
            db.session.commit()
            print("✅ Admin created")

        with app.test_request_context():
            print("🔗 Google OAuth Redirect URL:", url_for("google.login", _external=True))

    app.run(debug=True)
