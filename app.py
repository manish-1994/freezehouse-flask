from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from datetime import datetime
import requests
import random
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
mail = Mail(app)

# Telegram Configs
BOT_TOKEN = app.config['TELEGRAM_BOT_TOKEN']
ADMIN_CHAT_IDS = app.config['TELEGRAM_CHAT_IDS']


# ===========================
# Database Models
# ===========================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(150), unique=True, nullable=False)
    phone = db.Column(db.String(15), unique=True, nullable=False)
    aadhar = db.Column(db.String(12))
    dob = db.Column(db.String(20))
    password = db.Column(db.String(150), nullable=False)

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


# ===========================
# Helper
# ===========================

def notify_admins(message):
    for chat_id in ADMIN_CHAT_IDS:
        requests.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
            data={"chat_id": chat_id, "text": message}
        )


# ===========================
# Password Reset
# ===========================

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
        flash("No account found with that email.")
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
        password = generate_password_hash(request.form['password'])
        email = session.get('reset_email')
        user = User.query.filter_by(email=email).first()
        if user:
            user.password = password
            db.session.commit()
            session.pop('reset_email', None)
            flash("Password reset successful.")
            return redirect(url_for('login'))
    return render_template('reset_password.html')


# ===========================
# Authentication
# ===========================

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        phone = request.form['phone']
        aadhar = request.form['aadhar']
        dob = request.form['dob']
        password = generate_password_hash(request.form['password'])

        if User.query.filter_by(email=email).first() or \
           User.query.filter_by(username=username).first() or \
           User.query.filter_by(phone=phone).first():
            flash("User already exists.")
            return redirect(url_for('register'))

        user = User(username=username, email=email, phone=phone, aadhar=aadhar, dob=dob, password=password)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful.")
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, request.form['password']):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('dashboard'))
        elif username == 'admin' and request.form['password'] == 'admin':
            session['username'] = 'admin'
            return redirect(url_for('admin'))
        flash("Invalid credentials.")
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))


# ===========================
# Pages
# ===========================

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/services')
def services():
    return render_template('services.html')

@app.route('/benefits')
def benefits():
    return render_template('benefits.html', benefits=Benefit.query.all())

@app.route('/pricing')
def pricing():
    return render_template('pricing.html', items=Pricing.query.all())

@app.route('/contact')
def contact():
    return render_template('contact.html')


# ===========================
# Dashboard
# ===========================

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    bath_types = BathType.query.all()
    appointments = Appointment.query.filter_by(user_id=session['user_id']).all()
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

        appt = Appointment(user_id=session['user_id'], date=date, time=time,
                           reason=reason, bath_type=bath_type, price=price)
        db.session.add(appt)
        db.session.commit()
        user = User.query.get(session['user_id'])
        notify_admins(f"📅 New Appointment: {user.username} | {bath_type} | ₹{price} on {date} at {time}")
        return redirect(url_for('dashboard'))

    return render_template('dashboard.html', appointments=appointments,
                           bath_types=bath_types, booked_slots=booked_slots)


@app.route('/reschedule/<int:id>', methods=['GET', 'POST'])
def reschedule_appointment(id):
    appt = Appointment.query.get_or_404(id)
    if 'user_id' not in session or session['user_id'] != appt.user_id:
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
        notify_admins(f"🔁 Rescheduled: {appt.user_id} → {appt.date} {appt.time}")
        flash("Rescheduled.")
        return redirect(url_for('dashboard'))

    return render_template('reschedule.html', appointment=appt, bath_types=bath_types)


@app.route('/delete/<int:id>')
def delete_appointment(id):
    appt = Appointment.query.get_or_404(id)
    if 'user_id' in session and appt.user_id == session['user_id']:
        db.session.delete(appt)
        db.session.commit()
    return redirect(url_for('dashboard'))


# ===========================
# Admin Panel
# ===========================

@app.route('/admin')
def admin():
    if session.get('username') != 'admin':
        return redirect(url_for('login'))
    appointments = db.session.query(Appointment, User).join(User).all()
    return render_template('admin.html', appointments=appointments)

@app.route('/admin/delete/<int:id>')
def admin_delete(id):
    db.session.delete(Appointment.query.get_or_404(id))
    db.session.commit()
    return redirect(url_for('admin'))

@app.route('/delete_bath_type/<int:id>')
def delete_bath_type(id):
    bath = BathType.query.get_or_404(id)
    db.session.delete(bath)
    db.session.commit()
    flash('Bath type deleted.')
    return redirect(url_for('manage_bath_types'))

@app.route('/admin/bath-types', methods=['GET', 'POST'])
def manage_bath_types():
    if session.get('username') != 'admin':
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

@app.route('/admin/pricing', methods=['GET', 'POST'])
def manage_pricing():
    if session.get('username') != 'admin':
        return redirect(url_for('login'))
    if request.method == 'POST':
        db.session.add(Pricing(
            title=request.form['title'],
            description=request.form['description'],
            price=float(request.form['price'])
        ))
        db.session.commit()
    return render_template('manage_pricing.html', pricing=Pricing.query.all())

@app.route('/admin/benefits', methods=['GET', 'POST'])
def manage_benefits():
    if session.get('username') != 'admin':
        return redirect(url_for('login'))
    if request.method == 'POST':
        db.session.add(Benefit(
            title=request.form['title'],
            description=request.form['description']
        ))
        db.session.commit()
    return render_template('manage_benefits.html', benefits=Benefit.query.all())


# ===========================
# WhatsApp Booking
# ===========================

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

        notify_admins(f"📲 WhatsApp Booking: {name} | {bath_type} | ₹{price} on {date} at {time}")
        return "✅ WhatsApp Booking Confirmed"
    return render_template('whatsapp_booking.html', bath_types=bath_types)


# ===========================
# Run App
# ===========================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
