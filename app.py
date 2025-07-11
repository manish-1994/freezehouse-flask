from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import razorpay

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///appointments.db'
app.secret_key = 'your_secret_key_here'

db = SQLAlchemy(app)

razorpay_client = razorpay.Client(auth=("YOUR_KEY_ID", "YOUR_KEY_SECRET"))


# ========== Models ==========
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    phone = db.Column(db.String(15), nullable=False)
    aadhar = db.Column(db.String(12), nullable=False, unique=True)
    dob = db.Column(db.String(10), nullable=False)
    password = db.Column(db.String(150), nullable=False)

class BathType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
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



# ========== Routes ==========
@app.route('/')
def home():
    return render_template('index.html', show_particles=True)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        phone = request.form['phone']
        aadhar = request.form['aadhar']
        dob = request.form['dob']
        password = generate_password_hash(request.form['password'])

        if User.query.filter_by(username=username).first():
            flash("Username already exists")
            return redirect(url_for('register'))
        if User.query.filter_by(phone=phone).first():
            flash("Phone number already in use")
            return redirect(url_for('register'))
        if User.query.filter_by(aadhar=aadhar).first():
            flash("Aadhar number already registered")
            return redirect(url_for('register'))

        new_user = User(username=username, phone=phone, aadhar=aadhar, dob=dob, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', show_particles=True)

@app.route('/admin/pricing', methods=['GET', 'POST'])
def manage_pricing():
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = float(request.form['price'])

        new_item = Pricing(title=title, description=description, price=price)
        db.session.add(new_item)
        db.session.commit()
        flash("Pricing item added.")
        return redirect(url_for('manage_pricing'))

    pricing_items = Pricing.query.all()
    return render_template('manage_pricing.html', pricing_items=pricing_items, show_particles=True)
@app.route('/admin/pricing/delete/<int:id>')
def delete_pricing(id):
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login'))

    item = Pricing.query.get_or_404(id)
    db.session.delete(item)
    db.session.commit()
    flash("Pricing item deleted.")
    return redirect(url_for('manage_pricing'))

@app.route('/pricing')
def pricing():
    items = Pricing.query.all()
    return render_template('pricing.html', items=items, show_particles=True)


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
    return render_template('login.html', show_particles=True)

@app.route('/about')
def about():
    return render_template('about.html', show_particles=True)

@app.route('/services')
def services():
    return render_template('services.html', show_particles=True)

@app.route('/benefits')
def benefits():
    return render_template('benefits.html', show_particles=True)

@app.route('/contact')
def contact():
    return render_template('contact.html', show_particles=True)



@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    bath_types = BathType.query.all()
    booked_slots = [(slot.date, slot.time) for slot in Appointment.query.with_entities(Appointment.date, Appointment.time).all()]

    if request.method == 'POST':
        date = request.form['date']
        time = request.form['time']
        reason = request.form['reason']
        bath_type_name = request.form['bath_type']

        conflict = Appointment.query.filter_by(date=date, time=time).first()
        if conflict:
            flash("That slot is already booked.")
            return redirect(url_for('dashboard'))

        bath_type = BathType.query.filter_by(name=bath_type_name).first()
        price = bath_type.price if bath_type else 0

        appointment = Appointment(
            user_id=session['user_id'],
            date=date,
            time=time,
            reason=reason,
            bath_type=bath_type_name,
            price=price
        )
        db.session.add(appointment)
        db.session.commit()

        return redirect(url_for('pay', appointment_id=appointment.id))

    appointments = Appointment.query.filter_by(user_id=session['user_id']).all()
    return render_template('dashboard.html', appointments=appointments, bath_types=bath_types, booked_slots=booked_slots, show_particles=True)


# ========== Razorpay Payment ==========
@app.route('/pay/<int:appointment_id>')
def pay(appointment_id):
    if 'user_id' not in session:
        flash("Please login to continue")
        return redirect(url_for('login'))

    appointment = Appointment.query.get_or_404(appointment_id)

    order = razorpay_client.order.create(dict(
        amount=int(appointment.price * 100),
        currency='INR',
        payment_capture='1'
    ))

    return render_template("payment.html",
                           order_id=order['id'],
                           appointment=appointment,
                           key_id="YOUR_KEY_ID")


# ========== Admin ==========
@app.route('/admin')
def admin():
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login'))

    all_appointments = db.session.query(Appointment, User.phone).join(User, Appointment.user_id == User.id).all()
    return render_template('admin.html',
                           appointments=all_appointments,
                           show_bath_link=True,
                           show_phones=True,
                           show_particles=True)

@app.route('/admin/delete/<int:id>')
def admin_delete(id):
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login'))

    appointment = Appointment.query.get_or_404(id)
    db.session.delete(appointment)
    db.session.commit()
    flash("Appointment deleted by admin")
    return redirect(url_for('admin'))

@app.route('/admin/bath-types', methods=['GET', 'POST'])
def manage_bath_types():
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        price = float(request.form['price'])

        if BathType.query.filter_by(name=name).first():
            flash("Bath type already exists")
        else:
            new_bath = BathType(name=name, price=price)
            db.session.add(new_bath)
            db.session.commit()
            flash("Bath type added")

    bath_types = BathType.query.all()
    return render_template('manage_bath_types.html', bath_types=bath_types, show_particles=True)

@app.route('/admin/bath-types/delete/<int:id>')
def delete_bath_type(id):
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('login'))

    bath_type = BathType.query.get_or_404(id)
    db.session.delete(bath_type)
    db.session.commit()
    flash("Bath type deleted")
    return redirect(url_for('manage_bath_types'))


# ========== Run Server ==========
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
