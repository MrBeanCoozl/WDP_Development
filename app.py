from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, extract, or_, text
from sqlalchemy.pool import NullPool
from datetime import datetime, timedelta
from functools import wraps
import random
import os
import json
import smtplib
import re  # For password validation
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# --- 1. SETUP & CONFIGURATION ---
app = Flask(__name__)
app.secret_key = 'your_secret_key_here' 

basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'business_data.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- FIX: PREVENT DATABASE TIMEOUTS ---
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'poolclass': NullPool
}

# --- EMAIL CONFIGURATION ---
app.config['SMTP_SERVER'] = 'smtp.gmail.com'      
app.config['SMTP_PORT'] = 587                       
app.config['SMTP_EMAIL'] = 'limjiaan41@gmail.com'   
app.config['SMTP_PASSWORD'] = 'iilv ertj fvps wyai'   

db = SQLAlchemy(app)

# --- SYSTEM SETTINGS (Password Visibility) ---
SETTINGS_FILE = os.path.join(basedir, 'system_settings.json')

def get_system_settings():
    if not os.path.exists(SETTINGS_FILE): return {'show_passwords': False}
    try:
        with open(SETTINGS_FILE, 'r') as f: return json.load(f)
    except: return {'show_passwords': False}

def update_system_setting(key, value):
    settings = get_system_settings()
    settings[key] = value
    with open(SETTINGS_FILE, 'w') as f: json.dump(settings, f)

# --- TIME TRAVEL TRACKER ---
OFFSET_FILE = os.path.join(basedir, 'time_offset.json')

def get_total_skipped_days():
    if not os.path.exists(OFFSET_FILE): return 0
    try:
        with open(OFFSET_FILE, 'r') as f: return json.load(f).get('days_skipped', 0)
    except: return 0

def add_skipped_days(days):
    new_total = get_total_skipped_days() + days
    with open(OFFSET_FILE, 'w') as f: json.dump({'days_skipped': new_total}, f)

def reset_skipped_days():
    with open(OFFSET_FILE, 'w') as f: json.dump({'days_skipped': 0}, f)

# --- SMART PAGINATION FILTER (NEW FEATURE) ---
@app.template_filter('smart_pagination')
def smart_pagination_filter(pagination):
    """
    Generates a list of page items. 
    If there is a gap, it creates a 'gap' item with the midpoint page number.
    """
    if not pagination: return []
    
    # Standard iteration: 1 edge, 2 around current
    iterator = pagination.iter_pages(left_edge=1, right_edge=1, left_current=2, right_current=2)
    
    result = []
    last_page = 0
    gap_marker = False
    
    if iterator:
        for num in iterator:
            if num is None:
                gap_marker = True
            else:
                if gap_marker:
                    # CALCULATE MIDPOINT (Average)
                    # Example: Last=1, Current=10. Gap is 2..9. Midpoint = (1+10)//2 = 5.
                    midpoint = (last_page + num) // 2
                    result.append({'type': 'gap', 'page': midpoint})
                    gap_marker = False
                
                result.append({'type': 'page', 'page': num})
                last_page = num
                
    return result

# --- 2. DATABASE MODELS ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    custom_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False) 
    role = db.Column(db.String(20), default='Staff') 
    email = db.Column(db.String(120), unique=True, nullable=True)
    is_suspended = db.Column(db.Boolean, default=False)
    must_change_password = db.Column(db.Boolean, default=False)

class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    company = db.Column(db.String(100))

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_code = db.Column(db.String(50), unique=True) 
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    date_placed = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='Pending') 
    
    client = db.relationship('Client', backref=db.backref('orders', lazy=True))
    items = db.relationship('OrderItem', backref='order', lazy=True, cascade="all, delete-orphan")

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    item_name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    unit_price = db.Column(db.Float, nullable=False)
    total_price = db.Column(db.Float, nullable=False)

class Invoice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    invoice_code = db.Column(db.String(50), unique=True, nullable=False)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'))
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), default='Pending') 
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    date_due = db.Column(db.DateTime)
    
    client = db.relationship('Client', backref=db.backref('invoices', lazy=True))
    order = db.relationship('Order', backref=db.backref('invoice', uselist=False))

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    actor_type = db.Column(db.String(50), default='System') 
    actor_id = db.Column(db.String(50))
    action = db.Column(db.String(100), nullable=False)
    entity_type = db.Column(db.String(50)) 
    entity_id = db.Column(db.String(50))
    status = db.Column(db.String(50)) 
    description = db.Column(db.String(255))

# --- 3. HELPER FUNCTIONS ---

def log_action(actor_type, actor_id, action, entity_type, entity_id, status, description):
    try:
        log = AuditLog(actor_type=actor_type, actor_id=actor_id, action=action, entity_type=entity_type, entity_id=entity_id, status=status, description=description)
        db.session.add(log)
        db.session.commit()
    except: db.session.rollback()

def get_change(current, previous):
    if previous == 0: return 100 if current > 0 else 0
    return ((current - previous) / previous) * 100

def format_k(value):
    if value >= 1000000: return f"{value/1000000:.1f}M"
    if value >= 1000: return f"{value/1000:.1f}k"
    return str(value)

# --- EMAIL SENDER FUNCTION ---
def send_temp_password_email(user_email, temp_password):
    sender_email = app.config['SMTP_EMAIL']
    sender_password = app.config['SMTP_PASSWORD']
    smtp_server = app.config['SMTP_SERVER']
    smtp_port = app.config['SMTP_PORT']

    if 'your_email' in sender_email or 'your_app_password' in sender_password:
        print("\n" + "="*60)
        print(f" [DEBUG MODE] EMAIL NOT CONFIGURED")
        print(f" Target Email: {user_email}")
        print(f" TEMP PASSWORD: {temp_password}")
        print("="*60 + "\n")
        return False, "Simulated: Password printed to server console."

    if not user_email:
        return False, "User has no email address saved."

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = user_email
    msg['Subject'] = "Security Notice: Temporary Password Reset"

    body = f"""
    <h3>Password Reset Notice</h3>
    <p>Hello,</p>
    <p>Your administrator has reset your password.</p>
    <p><strong>Your new temporary password is:</strong> <span style="font-size: 16px; background: #eee; padding: 5px;">{temp_password}</span></p>
    <p>Please log in immediately and set a new personal password.</p>
    <br>
    <p>Regards,<br>System Admin</p>
    """
    msg.attach(MIMEText(body, 'html'))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, user_email, msg.as_string())
        server.quit()
        return True, "Email sent successfully."
    except Exception as e:
        print(f" [ERROR] EMAIL FAILED: {e}")
        return False, f"Failed: {str(e)}"

# --- PASSWORD VALIDATION HELPER ---
def is_password_strong(password):
    # Criteria: 8+ chars, 1 Uppercase, 1 Lowercase, 1 Number, 1 Special Char
    if len(password) < 8: return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password): return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password): return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password): return False, "Password must contain at least one number."
    if not re.search(r"[ !@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password): return False, "Password must contain at least one special character."
    return True, "Valid"

@app.before_request
def load_user():
    g.user = None
    if 'user_id' in session: g.user = User.query.get(session['user_id'])

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.user or g.user.role != 'SuperAdmin':
            flash("Access Denied: You do not have permission to view this page.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def operator_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.user or g.user.role == 'Staff':
            flash("Access Denied: Staff accounts cannot perform this action.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# --- 4. ROUTES ---

@app.route('/')
def home():
    if 'user_id' not in session: return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            if user.is_suspended:
                log_action('User', username, 'Login Blocked', 'Session', 'N/A', 'Failure', 'Suspended account attempted login')
                flash('Your account has been suspended. Please contact the Super Admin.')
                return render_template('login.html')
            
            session['user_id'] = user.id
            log_action('User', username, 'Login', 'Session', 'N/A', 'Success', 'User logged in successfully')
            
            if user.must_change_password: return redirect(url_for('change_password'))
            return redirect(url_for('dashboard'))
        else:
            log_action('User', username, 'Login Failed', 'Session', 'N/A', 'Failure', 'Invalid password attempt')
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session: return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        new_pass = request.form['new_password']
        confirm_pass = request.form['confirm_password']
        email_input = request.form.get('email')

        # 1. Check Matching
        if new_pass != confirm_pass:
            flash('Passwords do not match.')
            return redirect(url_for('change_password'))
        
        # 2. Check Strength
        is_strong, msg = is_password_strong(new_pass)
        if not is_strong:
            flash(f'Security Requirement: {msg}')
            return redirect(url_for('change_password'))
        
        # 3. Handle Email
        if not user.email:
            if not email_input:
                flash('You must provide a recovery email address.')
                return redirect(url_for('change_password'))
            if User.query.filter(User.email == email_input, User.id != user.id).first():
                flash('This email is already associated with another account.')
                return redirect(url_for('change_password'))
            user.email = email_input

        user.password = new_pass
        user.must_change_password = False 
        db.session.commit()
        log_action('User', user.username, 'Password/Email Updated', 'User', user.custom_id, 'Success', 'User updated credentials')
        return redirect(url_for('dashboard'))
        
    return render_template('change_password.html', user=user)

@app.route('/orders')
def orders():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    page = request.args.get('page', 1, type=int)
    search_q = request.args.get('search', '')
    status_filter = request.args.get('status', 'All')
    sort_by = request.args.get('sort', 'date_desc')

    query = Order.query

    if search_q:
        search_term = f"%{search_q}%"
        query = query.join(Client).filter(
            or_(
                Client.name.like(search_term),
                Order.description.like(search_term),
                Order.order_code.like(search_term)
            )
        )

    if status_filter != 'All':
        query = query.filter(Order.status == status_filter)

    if sort_by == 'price_high': query = query.order_by(Order.amount.desc())
    elif sort_by == 'price_low': query = query.order_by(Order.amount.asc())
    elif sort_by == 'date_asc': query = query.order_by(Order.date_placed.asc())
    else: query = query.order_by(Order.date_placed.desc())

    orders_pagination = query.paginate(page=page, per_page=10, error_out=False)
    return render_template('orders.html', orders=orders_pagination)

@app.route('/invoices', methods=['GET'])
def invoices():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    page = request.args.get('page', 1, type=int)
    today = datetime.now().date()
    overdue_invoices = Invoice.query.filter(
        or_(Invoice.status == 'Pending', Invoice.status == 'Sent'), 
        func.date(Invoice.date_due) < today
    ).all()
    
    if overdue_invoices:
        for inv in overdue_invoices:
            inv.status = 'Overdue'
            log_action('System', 'Auto-Check', 'Invoice Overdue', 'Invoice', inv.invoice_code, 'Warning', f'Invoice marked overdue (Due: {inv.date_due})')
        db.session.commit()

    search_query = request.args.get('search', '')
    status_filter = request.args.get('status', 'All')
    sort_by = request.args.get('sort', 'date_desc')

    query = Invoice.query

    if search_query:
        search_term = f"%{search_query}%"
        query = query.join(Client).filter(or_(Invoice.invoice_code.like(search_term), Client.name.like(search_term)))

    if status_filter != 'All':
        query = query.filter(Invoice.status == status_filter)

    if sort_by == 'amount_high': query = query.order_by(Invoice.amount.desc())
    elif sort_by == 'amount_low': query = query.order_by(Invoice.amount.asc())
    elif sort_by == 'date_asc': query = query.order_by(Invoice.date_created.asc())
    else: query = query.order_by(Invoice.date_created.desc())

    invoices_pagination = query.paginate(page=page, per_page=10, error_out=False)
    return render_template('invoices.html', invoices=invoices_pagination)

@app.route('/invoices/create/<int:order_id>', methods=['GET', 'POST'])
@operator_required
def create_invoice(order_id):
    order = Order.query.get_or_404(order_id)
    if request.method == 'POST':
        try:
            while True:
                new_code = f"INV-{datetime.now().strftime('%Y%m%d')}-{random.randint(100,999)}"
                if not Invoice.query.filter_by(invoice_code=new_code).first(): break

            new_invoice = Invoice(invoice_code=new_code, order_id=order.id, client_id=order.client_id, amount=order.amount, status='Sent', date_due=datetime.utcnow() + timedelta(days=30))
            db.session.add(new_invoice)
            order.status = 'Invoiced'
            db.session.commit()
            log_action('System', 'AI-Invoice-Bot', 'Invoice Generated', 'Invoice', new_code, 'Success', f'Auto-generated invoice for Order {order.order_code}')
            flash(f'Invoice {new_code} generated successfully!')
            return redirect(url_for('invoices'))
        except Exception as e:
            db.session.rollback()
            return redirect(url_for('error_page'))
    return render_template('create_invoice.html', order=order)

@app.route('/invoices/view/<int:invoice_id>')
def view_invoice(invoice_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    invoice = Invoice.query.get_or_404(invoice_id)
    return render_template('view_invoice.html', invoice=invoice)

@app.route('/invoices/edit/<int:invoice_id>', methods=['GET', 'POST'])
@admin_required
def edit_invoice(invoice_id):
    invoice = Invoice.query.get_or_404(invoice_id)
    if request.method == 'POST':
        try:
            new_amount = float(request.form['amount'])
            new_status = request.form['status']
            new_issue_date = datetime.strptime(request.form['date_created'], '%Y-%m-%d')
            new_due_date = datetime.strptime(request.form['date_due'], '%Y-%m-%d')
            
            invoice.amount = new_amount
            invoice.date_created = new_issue_date
            invoice.date_due = new_due_date
            
            today_date = datetime.now().date()
            due_date_obj = new_due_date.date()
            
            if new_status == 'Paid': invoice.status = 'Paid'
            elif due_date_obj < today_date:
                invoice.status = 'Overdue'
                flash(f'Notice: Status automatically set to Overdue because the due date ({due_date_obj}) is in the past.', 'warning')
            else:
                if new_status == 'Overdue': invoice.status = 'Pending'
                else: invoice.status = new_status

            db.session.commit()
            log_action('SuperAdmin', session.get('username'), 'Invoice Edited', 'Invoice', invoice.invoice_code, 'Success', "Updated invoice details")
            flash(f'Invoice {invoice.invoice_code} updated successfully.')
            return redirect(url_for('view_invoice', invoice_id=invoice.id))
        except Exception as e:
            db.session.rollback()
            return redirect(url_for('error_page'))
    return render_template('edit_invoice.html', invoice=invoice)

@app.route('/invoices/delete/<int:invoice_id>', methods=['POST'])
@admin_required
def delete_invoice(invoice_id):
    invoice = Invoice.query.get_or_404(invoice_id)
    try:
        if invoice.order: invoice.order.status = 'Pending'
        db.session.delete(invoice)
        db.session.commit()
        log_action('SuperAdmin', session.get('username'), 'Invoice Deleted', 'Invoice', invoice.invoice_code, 'Success', "Deleted invoice")
        flash('Invoice deleted successfully.')
        return redirect(url_for('invoices'))
    except:
        db.session.rollback()
        return redirect(url_for('error_page'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('login'))
    if User.query.get(session['user_id']).must_change_password: return redirect(url_for('change_password'))
    
    now = datetime.now()
    current_year = now.year
    last_year = current_year - 1
    current_month = now.month
    prev_month_date = now.replace(day=1) - timedelta(days=1)
    prev_month = prev_month_date.month
    prev_month_year = prev_month_date.year

    total_orders = Order.query.count()
    total_orders_prev = Order.query.filter(Order.date_placed < now - timedelta(days=30)).count()
    order_growth = get_change(total_orders, total_orders_prev)

    total_sales = db.session.query(func.sum(Invoice.amount)).scalar() or 0
    sales_prev = db.session.query(func.sum(Invoice.amount)).filter(Invoice.date_created < now.replace(day=1)).scalar() or 0
    sales_growth = get_change(total_sales, sales_prev)

    products_sold = Invoice.query.filter_by(status='Paid').count()
    products_prev = Invoice.query.filter(Invoice.status=='Paid', Invoice.date_created < now - timedelta(days=30)).count()
    product_growth = get_change(products_sold, products_prev)

    new_customers = Client.query.count() 
    customer_growth = 1.29 

    ytd_sales = db.session.query(func.sum(Order.amount)).filter(extract('year', Order.date_placed) == current_year).scalar() or 0
    last_ytd_sales = db.session.query(func.sum(Order.amount)).filter(extract('year', Order.date_placed) == last_year).scalar() or 0
    ytd_sales_growth = ytd_sales - last_ytd_sales

    ytd_count = Order.query.filter(extract('year', Order.date_placed) == current_year).count()
    last_ytd_count = Order.query.filter(extract('year', Order.date_placed) == last_year).count()
    ytd_count_growth = ytd_count - last_ytd_count

    mtd_sales = db.session.query(func.sum(Order.amount)).filter(extract('year', Order.date_placed) == current_year, extract('month', Order.date_placed) == current_month).scalar() or 0
    last_mtd_sales = db.session.query(func.sum(Order.amount)).filter(extract('year', Order.date_placed) == prev_month_year, extract('month', Order.date_placed) == prev_month).scalar() or 0
    mtd_sales_diff = mtd_sales - last_mtd_sales

    mtd_count = Order.query.filter(extract('year', Order.date_placed) == current_year, extract('month', Order.date_placed) == current_month).count()
    last_mtd_count = Order.query.filter(extract('year', Order.date_placed) == prev_month_year, extract('month', Order.date_placed) == prev_month).count()
    mtd_count_diff = mtd_count - last_mtd_count

    chart_invoice_months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sept', 'Oct', 'Nov', 'Dec']
    chart_invoice_reality = [0] * 12 
    monthly_sales_query = db.session.query(extract('month', Invoice.date_created), func.sum(Invoice.amount)).filter(extract('year', Invoice.date_created) == current_year).group_by(extract('month', Invoice.date_created)).all()
    for m, total in monthly_sales_query: chart_invoice_reality[int(m)-1] = total
        
    chart_invoice_target = [20000] * 12 

    ytd_invoiced_amt = db.session.query(func.sum(Order.amount)).filter(extract('year', Order.date_placed) == current_year, Order.status == 'Invoiced').scalar() or 0
    ytd_pending_amt = db.session.query(func.sum(Order.amount)).filter(extract('year', Order.date_placed) == current_year, Order.status == 'Pending').scalar() or 0
    chart_orders_ytd_pct = [round(ytd_invoiced_amt), round(ytd_pending_amt)]
    if sum(chart_orders_ytd_pct) == 0: chart_orders_ytd_pct = [0, 1]

    mtd_invoiced_amt = db.session.query(func.sum(Order.amount)).filter(extract('year', Order.date_placed) == current_year, extract('month', Order.date_placed) == current_month, Order.status == 'Invoiced').scalar() or 0
    mtd_pending_amt = db.session.query(func.sum(Order.amount)).filter(extract('year', Order.date_placed) == current_year, extract('month', Order.date_placed) == current_month, Order.status == 'Pending').scalar() or 0
    chart_orders_mtd_pct = [round(mtd_invoiced_amt), round(mtd_pending_amt)]
    if sum(chart_orders_mtd_pct) == 0: chart_orders_mtd_pct = [0, 1]

    top_clients_query = db.session.query(Client.name, func.sum(Invoice.amount)).join(Invoice).group_by(Client.name).order_by(func.sum(Invoice.amount).desc()).limit(4).all()
    top_clients_progress = []
    if top_clients_query:
        max_val = top_clients_query[0][1] if top_clients_query[0][1] > 0 else 1
        for client in top_clients_query:
            percent = min(round((client[1] / max_val) * 100), 100)
            top_clients_progress.append({'name': client[0], 'amount': client[1], 'percent': percent})

    chart_vol_service_labels = []
    chart_vol_data = []
    chart_service_data = []
    for i in range(4, -1, -1):
        day = now - timedelta(days=i)
        chart_vol_service_labels.append(day.strftime('%a'))
        chart_vol_data.append(Order.query.filter(func.date(Order.date_placed) == day.date()).count())
        chart_service_data.append(Invoice.query.filter(func.date(Invoice.date_created) == day.date()).count())
    
    return render_template('dashboard.html',
        total_orders=format_k(total_orders), order_growth=order_growth,
        total_sales=format_k(total_sales), sales_growth=sales_growth,
        products_sold=products_sold, product_growth=product_growth,
        new_customers=new_customers, customer_growth=customer_growth,
        ytd_sales=format_k(ytd_sales), ytd_sales_growth=format_k(abs(ytd_sales_growth)), ytd_pos=(ytd_sales_growth>=0),
        ytd_count=format_k(ytd_count), ytd_count_growth=format_k(abs(ytd_count_growth)), ytd_count_pos=(ytd_count_growth>=0),
        mtd_sales=format_k(mtd_sales), mtd_sales_diff=format_k(abs(mtd_sales_diff)), mtd_pos=(mtd_sales_diff>=0),
        mtd_count=mtd_count, mtd_count_diff=abs(mtd_count_diff), mtd_count_pos=(mtd_count_diff>=0),
        chart_invoice_months=chart_invoice_months, chart_invoice_reality=chart_invoice_reality, chart_invoice_target=chart_invoice_target,
        chart_orders_ytd_pct=chart_orders_ytd_pct, chart_orders_mtd_pct=chart_orders_mtd_pct,
        top_clients_progress=top_clients_progress,
        chart_sat_labels=['W1','W2','W3','W4','W5','W6','W7'], chart_sat_data=[85,82,88,84,91,87,94],
        chart_vol_service_labels=chart_vol_service_labels, chart_vol_data=chart_vol_data, chart_service_data=chart_service_data
    )

@app.route('/audit')
def audit_log():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    page = request.args.get('page', 1, type=int)
    search_q = request.args.get('q', '')
    action_filter = request.args.get('action_type', '')
    
    query = AuditLog.query
    
    if search_q:
        search_term = f"%{search_q}%"
        query = query.filter(
            or_(
                AuditLog.description.like(search_term),
                AuditLog.action.like(search_term),
                AuditLog.actor_id.like(search_term),
                AuditLog.actor_type.like(search_term),
                AuditLog.entity_id.like(search_term),
                AuditLog.entity_type.like(search_term),
                AuditLog.status.like(search_term),
                func.cast(AuditLog.timestamp, db.String).like(search_term)
            )
        )
        
    if action_filter and action_filter != 'All':
        query = query.filter(AuditLog.action == action_filter)
        
    logs_pagination = query.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=10, error_out=False)
    unique_actions = [r.action for r in db.session.query(AuditLog.action).distinct()]
    return render_template('audit_log.html', logs=logs_pagination, unique_actions=unique_actions)

@app.route('/audit/view/<int:log_id>')
def audit_details(log_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    log = AuditLog.query.get_or_404(log_id)
    return render_template('audit_details.html', log=log)

@app.route('/admin/panel')
@admin_required
def admin_panel():
    search_q = request.args.get('q', '')
    query = User.query
    if search_q: query = query.filter(or_(User.custom_id.like(f"%{search_q}%"), User.username.like(f"%{search_q}%")))
    users = query.all()
    
    # PASS SETTINGS TO TEMPLATE
    settings = get_system_settings()
    show_passwords = settings.get('show_passwords', False)
    
    return render_template('admin_panel.html', users=users, show_passwords=show_passwords)

@app.route('/admin/create', methods=['GET', 'POST'])
@admin_required
def create_admin():
    if request.method == 'POST':
        if User.query.filter_by(username=request.form['username']).first():
            flash('Username already exists.')
            return redirect(url_for('create_admin'))
        count = User.query.count() + 1
        new_user = User(
            custom_id=f"USR-{datetime.now().year}-{count:03d}",
            username=request.form['username'],
            password=request.form['password'],
            role=request.form['role'],
            must_change_password=True
        )
        db.session.add(new_user)
        db.session.commit()
        log_action('SuperAdmin', session.get('username'), 'Account Created', 'User', new_user.custom_id, 'Success', f'Created new {new_user.role} user: {new_user.username}')
        return redirect(url_for('admin_panel'))
    return render_template('admin_create.html')

@app.route('/admin/edit/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_admin(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == g.user.id:
        flash("You cannot edit your own authority level.", "danger")
        return redirect(url_for('admin_panel'))

    if request.method == 'POST':
        admin_password = request.form.get('admin_password')
        if not admin_password or admin_password != g.user.password:
            flash("Incorrect password. Authority change denied.", "danger")
            log_action('SuperAdmin', g.user.username, 'Edit Role Failed', 'User', user.custom_id, 'Failure', 'Incorrect password confirmation')
            return redirect(url_for('edit_admin', user_id=user.id))

        old_role = user.role
        new_role = request.form['role']
        
        user.role = new_role
        db.session.commit()
        
        log_action('SuperAdmin', g.user.username, 'Authority Changed', 'User', user.custom_id, 'Success', f'Changed role from {old_role} to {new_role}')
        flash(f'User {user.username} updated to {new_role}.', 'success')
        return redirect(url_for('admin_panel'))
        
    return render_template('admin_edit.html', user=user)

# --- UPDATED ADMIN RESET PASSWORD (DB COMMIT FIRST + LOG HISTORY) ---
@app.route('/admin/reset_password/<int:user_id>', methods=['POST'])
@admin_required
def reset_password(user_id):
    user = User.query.get(user_id)
    temp_pass = request.form['temp_password']
    new_username = request.form.get('new_username')
    new_email = request.form.get('new_email') # Get email from form
    
    if new_username: 
        user.username = new_username
    
    # 1. Capture the OLD email before we change it (for logging history)
    old_email = user.email 

    # 2. Update to NEW Email if provided
    if new_email and new_email.strip():
        user.email = new_email.strip()
    
    user.password = temp_pass
    user.must_change_password = True
    
    # Capture email for sending AFTER commit (so DB connection is free)
    target_email = user.email
    
    # 3. COMMIT TO DB IMMEDIATELY (RELEASES LOCK)
    db.session.commit()
    
    # 4. SEND EMAIL
    email_status = False
    email_msg = "No email on file."
    
    if target_email:
        success, msg = send_temp_password_email(target_email, temp_pass)
        email_status = success
        email_msg = msg
    
    # 5. FLASH RESULT
    if email_status:
        flash(f'Reset successful. Email sent to {target_email}.', 'success')
        log_type = 'Success'
    else:
        # Show specific message if simulated
        if "Simulated" in email_msg:
            flash(f'Simulated Reset: Password printed to server console.', 'warning')
        else:
            flash(f'Reset successful, but EMAIL FAILED: {email_msg} (Check Console for Password)', 'warning')
        log_type = 'Warning'

    # 6. Update the Log Message to include the history (OLD EMAIL)
    change_note = ""
    if old_email and old_email != user.email:
        change_note = f" (Email changed from {old_email} to {user.email})"

    log_action('SuperAdmin', session.get('username'), 'Credentials Updated', 'User', user.custom_id, log_type, f'Reset password. Email: {email_msg}{change_note}')
    return redirect(url_for('admin_panel'))

@app.route('/admin/suspend/<int:user_id>', methods=['POST'])
@admin_required
def suspend_admin(user_id):
    user = User.query.get(user_id)
    user.is_suspended = not user.is_suspended
    db.session.commit()
    
    action_type = "Account Suspended" if user.is_suspended else "Account Reactivated"
    log_action('SuperAdmin', session.get('username'), action_type, 'User', user.custom_id, 'Warning', f'User {user.username} status toggled.')
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_admin(user_id):
    user = User.query.get(user_id)
    if user:
        u_name = user.username
        u_id = user.custom_id
        db.session.delete(user)
        db.session.commit()
        log_action('SuperAdmin', session.get('username'), 'Account Deleted', 'User', u_id, 'Danger', f'Deleted user: {u_name}')
    return redirect(url_for('admin_panel'))

@app.route('/admin/danger_zone', methods=['GET', 'POST'])
@admin_required
def danger_zone():
    current_skipped = get_total_skipped_days()
    # FETCH SETTINGS
    settings = get_system_settings()
    show_passwords = settings.get('show_passwords', False)
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'toggle_passwords':
            new_state = not show_passwords
            update_system_setting('show_passwords', new_state)
            log_action('SuperAdmin', session.get('username'), 'Security Policy Change', 'System', 'ALL', 'Warning', f'Admin password visibility set to {new_state}')
            flash(f'Password visibility turned {"ON" if new_state else "OFF"}.', 'warning' if new_state else 'success')
            return redirect(url_for('danger_zone'))

        elif action == 'wipe':
            try:
                Invoice.query.delete()
                OrderItem.query.delete()
                Order.query.delete()
                Client.query.delete()
                AuditLog.query.delete()
                reset_skipped_days()
                db.session.commit()
                log_action('SuperAdmin', session.get('username'), 'Hard Reset', 'System', 'ALL', 'Success', 'Wiped all business data.')
                flash('SYSTEM WIPE SUCCESSFUL: All data cleared.', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'Error during wipe: {str(e)}', 'danger')
        
        elif action == 'time_skip':
            try:
                days = int(request.form.get('days', 0))
                if days > 0:
                    delta = timedelta(days=days)
                    orders = Order.query.all()
                    for o in orders: o.date_placed -= delta
                    invoices = Invoice.query.all()
                    for i in invoices:
                        i.date_created -= delta
                        i.date_due -= delta
                        if i.status in ['Pending', 'Sent'] and i.date_due < datetime.now():
                            i.status = 'Overdue'
                    logs = AuditLog.query.all()
                    for l in logs: l.timestamp -= delta
                    
                    add_skipped_days(days)
                    db.session.commit()
                    log_action('SuperAdmin', session.get('username'), 'Time Travel', 'System', 'ALL', 'Success', f'Shifted data back by {days} days.')
                    flash(f'Time Travel Successful: Data is now {days} days older.', 'success')
            except Exception as e:
                db.session.rollback()
                flash(f'Error: {str(e)}', 'danger')

        elif action == 'undo_time_skip':
            try:
                days_to_restore = get_total_skipped_days()
                if days_to_restore > 0:
                    delta = timedelta(days=days_to_restore)
                    orders = Order.query.all()
                    for o in orders: o.date_placed += delta
                    invoices = Invoice.query.all()
                    today = datetime.now()
                    for i in invoices:
                        i.date_created += delta
                        i.date_due += delta
                        if i.status == 'Overdue' and i.date_due >= today:
                            i.status = 'Pending'
                    logs = AuditLog.query.all()
                    for l in logs: l.timestamp += delta
                    
                    reset_skipped_days()
                    db.session.commit()
                    log_action('SuperAdmin', session.get('username'), 'Undo Time Travel', 'System', 'ALL', 'Success', f'Restored {days_to_restore} days.')
                    flash(f'Undo Successful: System restored to original time.', 'success')
                else:
                    flash('Time is already synchronized.', 'secondary')
            except Exception as e:
                db.session.rollback()
                flash(f'Error: {str(e)}', 'danger')

        return redirect(url_for('dashboard'))
            
    return render_template('danger_zone.html', days_skipped=current_skipped, show_passwords=show_passwords)

@app.route('/generate_bulk_data')
@operator_required
def generate_bulk_data():
    client_names = ["Vogue Styles", "Urban Trends Boutique", "Silk & Cotton Co", "Velvet Runway", "Modern Menswear", "Chic Streetwear", "Luxe Fabrics Ltd", "Denim Supply Depot", "Kids Corner Fashion", "Summer Breeze Apparel", "Winter Warmth Gear", "Athletic Aesthetics", "Vintage Threads", "Haute Couture House", "Basic Essentials", "Fashion Forward Inc"]
    clients = []
    for name in client_names:
        exists = Client.query.filter_by(name=name).first()
        if not exists:
            c = Client(name=name, email=f"contact@{name.replace(' ','').lower()}.com", company=name)
            db.session.add(c)
            clients.append(c)
        else: clients.append(exists)
    db.session.commit()
    
    # Define Item Names and their Price Ranges (Min, Max)
    item_definitions = [
        ("Cotton Crew Neck T-Shirt", 15, 35),
        ("Slim Fit Denim Jeans", 50, 150),
        ("Silk Floral Scarf", 30, 80),
        ("Leather Biker Jacket", 150, 450),
        ("Summer Breeze Sundress", 40, 90),
        ("Canvas Low-Top Sneakers", 30, 80),
        ("Classic Oxford Shirt", 40, 100),
        ("Wool Blend Coat", 120, 300),
        ("Athletic Running Shorts", 20, 50),
        ("Knitted Sweater", 60, 140),
        ("Designer Sunglasses", 80, 250),
        ("Formal Leather Belt", 25, 70),
        ("Ankle Boots", 80, 180),
        ("Casual Hoodie", 35, 85),
        ("Pleated Midi Skirt", 45, 95),
        ("Graphic Print Tee", 20, 45),
        ("Chino Trousers", 45, 90)
    ]
    
    # Cents variants for realistic pricing
    cents_options = [0.00, 0.50, 0.90, 0.95, 0.99, 0.25, 0.75, 0.55, 0.45]

    start_date = datetime.now() - timedelta(days=730) 
    end_date = datetime.now()
    
    for _ in range(150): 
        days_between = (end_date - start_date).days
        order_date = start_date + timedelta(days=random.randrange(days_between))
        client = random.choice(clients)
        
        # 40% chance of single item, 60% chance of multi-item (2-6 items)
        if random.random() < 0.4:
            num_items = 1
        else:
            num_items = random.randint(2, 6)
        
        order_items_data = []
        total_amount = 0
        
        for _ in range(num_items):
            base_name, min_p, max_p = random.choice(item_definitions)
            
            # Generate random price within range + realistic cents ending
            dollars = random.randint(min_p, max_p)
            cents = random.choice(cents_options)
            unit_price = dollars + cents
            
            qty = random.randint(1, 12)
            line_total = round(qty * unit_price, 2)
            
            total_amount += line_total
            order_items_data.append({'name': base_name, 'qty': qty, 'price': unit_price, 'total': line_total})
            
        desc = f"Bulk Order - {num_items} Items" if num_items > 1 else order_items_data[0]['name']
        status = 'Invoiced' if random.random() > 0.3 else 'Pending'

        # UNIQUE ORDER CODE CHECK
        while True:
            code = f"ORD-{order_date.strftime('%Y%m')}-{random.randint(1000,99999)}"
            if not Order.query.filter_by(order_code=code).first(): break
        
        o = Order(order_code=code, client_id=client.id, description=desc, amount=total_amount, date_placed=order_date, status=status)
        db.session.add(o)
        db.session.commit()
        
        # Create Items
        for item in order_items_data:
            oi = OrderItem(order_id=o.id, item_name=item['name'], quantity=item['qty'], unit_price=item['price'], total_price=item['total'])
            db.session.add(oi)
            
        if status == 'Invoiced':
            # UNIQUE INVOICE CODE CHECK
            while True:
                inv_code = f"INV-{order_date.strftime('%Y%m')}-{random.randint(1000,99999)}"
                if not Invoice.query.filter_by(invoice_code=inv_code).first(): break
            
            inv = Invoice(invoice_code=inv_code, order_id=o.id, client_id=client.id, amount=total_amount, status='Paid', date_created=order_date, date_due=order_date)
            db.session.add(inv)
            
    db.session.commit()
    flash("Success! Added 150+ realistic fashion orders with varied items and pricing.")
    return redirect(url_for('dashboard'))

@app.route('/guide')
def guide(): return render_template('guide.html')

@app.route('/error')
def error_page(): return render_template('error.html')

if __name__ == '__main__':
    with app.app_context():
        try:
            with db.engine.connect() as conn:
                try: conn.execute(text("ALTER TABLE `order` ADD COLUMN order_code VARCHAR(50)"))
                except: pass
        except: pass
        
        db.create_all()
        
        # --- DATA MIGRATION ---
        # Consolidate "Suspended User" to "Account Suspended"
        try:
            db.session.execute(text("UPDATE audit_log SET action = 'Account Suspended' WHERE action = 'Suspended User'"))
            db.session.execute(text("UPDATE audit_log SET action = 'Account Reactivated' WHERE action = 'Re-activated User'"))
            db.session.execute(text("UPDATE audit_log SET action = 'Account Deleted' WHERE action = 'Delete User'"))
            db.session.execute(text("UPDATE audit_log SET action = 'Authority Changed' WHERE action = 'Edit User Role'"))
            db.session.execute(text("UPDATE audit_log SET action = 'Password Changed' WHERE action = 'Password Change'"))
            db.session.commit()
        except Exception as e:
            print(f"Migration Notice: {e}")
        # ----------------------

        if not User.query.first():
            admin = User(username='admin', password='password123', role='SuperAdmin', custom_id='USR-ADMIN-001')
            db.session.add(admin)
            db.session.commit()
            
    app.run(debug=True)