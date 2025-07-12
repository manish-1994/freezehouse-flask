from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///appointments.db'
db = SQLAlchemy(app)

# Telegram setup
BOT_TOKEN = "7598988171:AAGylvhUVZeYBIgYvOXRCsJfChjq8ohoGRs"
ADMIN_CHAT_IDS = ["6511211034"]  # Add other admin IDs as strings

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    phone = db.Column(db.String(15), unique=True, nullable=False)
    aadhar = db.Column(db.String(12))
    dob = db.Column(db.String(20))
    password = db.Column(db.String(150), nullable=False)

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
    description = db.Column(db.String(250))
    price = db.Column(db.Float)

class Benefit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(250))

# Telegram Notify
def notify_admins(message):
    for chat_id in ADMIN_CHAT_IDS:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        data = {"chat_id": chat_id, "text": message}
        requests.post(url, data=data)

# Routes
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
    benefits = Benefit.query.all()
    return render_template('benefits.html', benefits=benefits)

@app.route('/pricing')
def pricing():
    pricing = Pricing.query.all()
    return render_template('pricing.html', pricing=pricing)

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        phone = request.form['phone']
        aadhar = request.form['aadhar']
        dob = request.form['dob']
        password = generate_password_hash(request.form['password'])

        if User.query.filter((User.username == username) | (User.phone == phone)).first():
            flash("Username or phone already registered.")
            return redirect(url_for('register'))

        user = User(username=username, phone=phone, aadhar=aadhar, dob=dob, password=password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == 'admin' and password == 'admin':
            session['username'] = 'admin'
            return redirect(url_for('admin'))

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('dashboard'))
        flash("Invalid credentials")
    return render_template('login.html')

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
        bath_type_name = request.form['bath_type']
        reason = request.form['reason']

        if datetime.strptime(date, "%Y-%m-%d").date() < datetime.today().date():
            flash("Cannot book past dates.")
            return redirect(url_for('dashboard'))

        if Appointment.query.filter_by(date=date, time=time).first():
            flash("Slot already booked.")
            return redirect(url_for('dashboard'))

        bath = BathType.query.filter_by(name=bath_type_name).first()
        price = bath.price if bath else 0

        appointment = Appointment(user_id=session['user_id'], date=date, time=time,
                                  reason=reason, bath_type=bath_type_name, price=price)
        db.session.add(appointment)
        db.session.commit()

        user = User.query.get(session['user_id'])
        notify_admins(f"📅 New Appointment:\n👤 {user.username}\n📞 {user.phone}\n🛁 {bath_type_name}\n🗓 {date} at {time}\n₹{price}\n📝 {reason}")

        return redirect(url_for('dashboard'))

    return render_template('dashboard.html', appointments=appointments, bath_types=bath_types, booked_slots=booked_slots)

@app.route('/reschedule/<int:id>', methods=['GET', 'POST'])
def reschedule_appointment(id):
    appointment = Appointment.query.get_or_404(id)
    if 'user_id' not in session or session['user_id'] != appointment.user_id:
        return redirect(url_for('dashboard'))

    bath_types = BathType.query.all()

    if request.method == 'POST':
        date = request.form['date']
        time = request.form['time']

        if Appointment.query.filter(Appointment.id != id, Appointment.date == date, Appointment.time == time).first():
            flash("Slot already booked.")
            return redirect(url_for('reschedule_appointment', id=id))

        appointment.date = date
        appointment.time = time
        appointment.reason = request.form['reason']
        appointment.bath_type = request.form['bath_type']
        bath = BathType.query.filter_by(name=appointment.bath_type).first()
        appointment.price = bath.price if bath else 0

        db.session.commit()
        flash("Rescheduled successfully.")
        return redirect(url_for('dashboard'))

    return render_template('reschedule.html', appointment=appointment, bath_types=bath_types)

@app.route('/delete/<int:id>')
def delete_appointment(id):
    appointment = Appointment.query.get_or_404(id)
    if 'user_id' in session and appointment.user_id == session['user_id']:
        db.session.delete(appointment)
        db.session.commit()
    return redirect(url_for('dashboard'))

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

        if Appointment.query.filter_by(date=date, time=time).first():
            return "Slot already booked."

        user = User.query.filter_by(phone=phone).first()
        if not user:
            user = User(username=name, phone=phone, password=generate_password_hash('default123'))
            db.session.add(user)
            db.session.commit()

        bath = BathType.query.filter_by(name=bath_type).first()
        price = bath.price if bath else 0

        appointment = Appointment(user_id=user.id, date=date, time=time, reason=reason,
                                  bath_type=bath_type, price=price)
        db.session.add(appointment)
        db.session.commit()

        notify_admins(f"📱 WhatsApp Booking:\n👤 {name}\n📞 {phone}\n🛁 {bath_type}\n🗓 {date} at {time}\n₹{price}\n📝 {reason}")
        return "Appointment booked via WhatsApp. Admin notified."
    return render_template('whatsapp_booking.html', bath_types=bath_types)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/admin')
def admin():
    if session.get('username') != 'admin':
        return redirect(url_for('login'))
    appointments = db.session.query(Appointment, User).join(User, Appointment.user_id == User.id).order_by(Appointment.date.desc()).all()
    return render_template('admin.html', appointments=appointments)

@app.route('/admin/delete/<int:id>')
def admin_delete(id):
    if session.get('username') != 'admin':
        return redirect(url_for('login'))
    appointment = Appointment.query.get_or_404(id)
    db.session.delete(appointment)
    db.session.commit()
    flash("Appointment deleted.")
    return redirect(url_for('admin'))

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
    bath_types = BathType.query.all()
    return render_template('manage_bath_types.html', bath_types=bath_types)

@app.route('/admin/bath-types/delete/<int:id>')
def delete_bath_type(id):
    if session.get('username') != 'admin':
        return redirect(url_for('login'))
    bath_type = BathType.query.get_or_404(id)
    db.session.delete(bath_type)
    db.session.commit()
    return redirect(url_for('manage_bath_types'))

@app.route('/admin/pricing', methods=['GET', 'POST'])
def manage_pricing():
    if session.get('username') != 'admin':
        return redirect(url_for('login'))
    if request.method == 'POST':
        db.session.add(Pricing(title=request.form['title'],
                               description=request.form['description'],
                               price=float(request.form['price'])))
        db.session.commit()
    pricing = Pricing.query.all()
    return render_template('manage_pricing.html', pricing=pricing)

@app.route('/admin/pricing/delete/<int:id>')
def delete_pricing(id):
    if session.get('username') != 'admin':
        return redirect(url_for('login'))
    item = Pricing.query.get_or_404(id)
    db.session.delete(item)
    db.session.commit()
    return redirect(url_for('manage_pricing'))

@app.route('/admin/benefits', methods=['GET', 'POST'])
def manage_benefits():
    if session.get('username') != 'admin':
        return redirect(url_for('login'))
    if request.method == 'POST':
        db.session.add(Benefit(title=request.form['title'], description=request.form['description']))
        db.session.commit()
    benefits = Benefit.query.all()
    return render_template('manage_benefits.html', benefits=benefits)

@app.route('/admin/benefits/delete/<int:id>')
def delete_benefit(id):
    if session.get('username') != 'admin':
        return redirect(url_for('login'))
    benefit = Benefit.query.get_or_404(id)
    db.session.delete(benefit)
    db.session.commit()
    return redirect(url_for('manage_benefits'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
