from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, extract, or_, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.pool import NullPool
from datetime import datetime, timedelta
from functools import wraps
import random
import os
import json
import smtplib
import re
import traceback
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# --- 1. SETUP & CONFIGURATION ---
app = Flask(__name__)
app.secret_key = 'your_secret_key_here' 

basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'business_data.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'poolclass': NullPool
}

# --- EMAIL CONFIGURATION ---
app.config['SMTP_SERVER'] = 'smtp.gmail.com'
app.config['SMTP_PORT'] = 587
# .strip() added to remove any accidental whitespace from copy-pasting
app.config['SMTP_EMAIL'] = 'limjiaan41@gmail.com'.strip()
app.config['SMTP_PASSWORD'] = 'xfxx kqbw mrsv wsvc'.strip()

db = SQLAlchemy(app)

# --- CONFIG CONSTANTS ---
MAX_LOGIN_ATTEMPTS = 5

# --- SYSTEM SETTINGS ---
SETTINGS_FILE = os.path.join(basedir, 'system_settings.json')
TARGETS_FILE = os.path.join(basedir, 'sales_targets.json')

def get_system_settings():
    default_settings = {'show_passwords': False, 'email_required': True} 
    if not os.path.exists(SETTINGS_FILE): return default_settings
    try:
        with open(SETTINGS_FILE, 'r') as f: 
            saved = json.load(f)
            for k, v in default_settings.items():
                if k not in saved: saved[k] = v
            return saved
    except: return default_settings

def update_system_setting(key, value):
    settings = get_system_settings()
    settings[key] = value
    with open(SETTINGS_FILE, 'w') as f: json.dump(settings, f)

# --- SALES TARGET HELPERS ---
def get_sales_targets():
    default_targets = [20000] * 12
    if not os.path.exists(TARGETS_FILE): return default_targets
    try:
        with open(TARGETS_FILE, 'r') as f:
            data = json.load(f)
            return data.get('targets', default_targets)
    except: return default_targets

def save_sales_targets(targets):
    with open(TARGETS_FILE, 'w') as f:
        json.dump({'targets': targets}, f)

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

# --- SMART PAGINATION FILTER ---
@app.template_filter('smart_pagination')
def smart_pagination_filter(pagination):
    if not pagination: return []
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
    failed_attempts = db.Column(db.Integer, default=0) 

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
    except Exception as e:
        db.session.rollback()
        print(f"Logging Failed: {e}")

def get_change(current, previous):
    try:
        if previous == 0: return 100 if current > 0 else 0
        return ((current - previous) / previous) * 100
    except:
        return 0

def format_k(value):
    try:
        if value is None: return "0"
        if value >= 1000000: return f"{value/1000000:.1f}M"
        if value >= 1000: return f"{value/1000:.1f}k"
        return str(value)
    except:
        return "Err"

# --- EMAIL SENDER FUNCTION (FIXED & DEBUGGED) ---
def send_temp_password_email(user_email, temp_password):
    sender_email = app.config['SMTP_EMAIL']
    sender_password = app.config['SMTP_PASSWORD']
    smtp_server = app.config['SMTP_SERVER']
    smtp_port = app.config['SMTP_PORT']

    # 1. Validate Email Existence
    if not user_email or "@" not in user_email:
        print(" [ERROR] Invalid user email format.")
        return False, "Invalid email address format."

    # 2. Check for Default Credentials
    if 'your_email' in sender_email or 'your_app_password' in sender_password:
        return False, "System Error: Default SMTP credentials in use."

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
        # 3. Connection and Auth
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        
        # CRITICAL FIX: Ensure password string has absolutely no spaces
        clean_password = sender_password.replace(' ', '').strip()
        
        server.login(sender_email, clean_password)
        server.sendmail(sender_email, user_email, msg.as_string())
        server.quit()
        
        print(f" [SUCCESS] Email sent to {user_email}")
        return True, "Email sent successfully."
    except smtplib.SMTPAuthenticationError:
        print(" [ERROR] SMTP Auth Failed. Check App Password.")
        return False, "Authentication Failed (Check Server Logs)"
    except Exception as e:
        print(f" [ERROR] EMAIL FAILED: {e}")
        return False, f"Error: {str(e)}"

# --- PASSWORD VALIDATION HELPER ---
def is_password_strong(password):
    try:
        if len(password) < 8: return False, "Password must be at least 8 characters long."
        if not re.search(r"[A-Z]", password): return False, "Password must contain at least one uppercase letter."
        if not re.search(r"[a-z]", password): return False, "Password must contain at least one lowercase letter."
        if not re.search(r"\d", password): return False, "Password must contain at least one number."
        if not re.search(r"[ !@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password): return False, "Password must contain at least one special character."
        return True, "Valid"
    except:
        return False, "Invalid password format."

@app.before_request
def load_user():
    g.user = None
    if 'user_id' in session: 
        try:
            g.user = User.query.get(session['user_id'])
        except:
            session.clear() 

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

# --- ROUTES ---

@app.route('/')
def home():
    if 'user_id' not in session: return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username = request.form['username']
            password = request.form['password']
            user = User.query.filter_by(username=username).first()
            
            if user:
                # 1. Check if ALREADY suspended
                if user.is_suspended:
                    log_action('User', username, 'Login Blocked', 'Session', 'N/A', 'Failure', 'Suspended account attempted login')
                    flash('Your account has been suspended due to security reasons. Please contact the Super Admin.', 'danger')
                    return render_template('login.html')
                
                # 2. Check Password
                if user.password == password:
                    # Success: Reset counter
                    user.failed_attempts = 0
                    db.session.commit()
                    
                    session['user_id'] = user.id
                    log_action('User', username, 'Login', 'User', user.custom_id, 'Success', 'User logged in successfully')
                    
                    if user.must_change_password: return redirect(url_for('change_password'))
                    return redirect(url_for('dashboard'))
                else:
                    # Failure: Increment counter
                    current_attempts = (user.failed_attempts or 0) + 1
                    user.failed_attempts = current_attempts
                    
                    # 3. Check Threshold
                    if current_attempts >= MAX_LOGIN_ATTEMPTS:
                        user.is_suspended = True
                        db.session.commit()
                        
                        log_action('System', 'Security Bot', 'Account Suspended', 'User', user.custom_id, 'Danger', f'Suspended after {current_attempts} failed login attempts')
                        flash('Security Alert: Your account has been suspended due to too many failed attempts.', 'danger')
                    else:
                        attempts_left = MAX_LOGIN_ATTEMPTS - current_attempts
                        db.session.commit()
                        
                        # Log User ID if username exists
                        log_action('User', username, 'Login Failed', 'User', user.custom_id, 'Failure', f'Invalid password. {attempts_left} attempts remaining.')
                        flash(f'Invalid credentials. {attempts_left} attempts remaining before suspension.', 'warning')
            else:
                # Unknown user (no User ID available)
                log_action('User', username, 'Login Failed', 'Session', 'N/A', 'Failure', 'Unknown username')
                flash('Invalid credentials')
                
        except Exception as e:
            flash(f"System Error: {str(e)}", "danger")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    try:
        user = User.query.get(session['user_id'])
        if not user: 
            session.clear()
            return redirect(url_for('login'))
        
        settings = get_system_settings()
        email_required = settings.get('email_required', True)

        if request.method == 'POST':
            new_pass = request.form['new_password']
            confirm_pass = request.form['confirm_password']
            email_input = request.form.get('email')

            if new_pass != confirm_pass:
                flash('Passwords do not match.')
                return redirect(url_for('change_password'))
            
            is_strong, msg = is_password_strong(new_pass)
            if not is_strong:
                flash(f'Security Requirement: {msg}')
                return redirect(url_for('change_password'))
            
            if not user.email:
                if email_required: 
                    if not email_input:
                        flash('You must provide a recovery email address.')
                        return redirect(url_for('change_password'))
                
                if email_input: 
                    existing = User.query.filter(User.email == email_input, User.id != user.id).first()
                    if existing:
                        flash('This email is already associated with another account.')
                        return redirect(url_for('change_password'))
                    user.email = email_input

            user.password = new_pass
            user.must_change_password = False 
            
            db.session.commit()
            log_action('User', user.username, 'Password/Email Updated', 'User', user.custom_id, 'Success', 'User updated credentials')
            return redirect(url_for('dashboard'))
            
    except Exception as e:
        db.session.rollback()
        flash(f"Error updating credentials: {str(e)}", "danger")
        return redirect(url_for('change_password'))
    
    return render_template('change_password.html', user=user, email_required=email_required)

@app.route('/orders')
def orders():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    try:
        page = request.args.get('page', 1, type=int)
        search_q = request.args.get('search', '')
        status_filter = request.args.get('status', 'Pending')
        sort_by = request.args.get('sort', 'date_desc')

        query = Order.query

        if search_q:
            clean_input = search_q.strip()
            clean_input_no_hash = clean_input.replace('#', '')
            search_parts = clean_input_no_hash.split()
            robust_pattern = "%" + "%".join(search_parts) + "%"

            query = query.join(Client).filter(
                or_(
                    Client.name.like(robust_pattern),
                    Client.company.like(robust_pattern), # Added Company
                    Order.description.like(robust_pattern),
                    Order.order_code.like(robust_pattern)
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
    except Exception as e:
        print(traceback.format_exc())
        return render_template('error.html', error_message="Could not load orders. Please try again.")

@app.route('/invoices', methods=['GET'])
def invoices():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    try:
        page = request.args.get('page', 1, type=int)
        today = datetime.now().date()
        try:
            overdue_invoices = Invoice.query.filter(
                or_(Invoice.status == 'Pending', Invoice.status == 'Sent'), 
                func.date(Invoice.date_due) < today
            ).all()
            if overdue_invoices:
                for inv in overdue_invoices:
                    inv.status = 'Overdue'
                db.session.commit()
        except:
            db.session.rollback()

        search_query = request.args.get('search', '')
        status_filter = request.args.get('status', 'All')
        sort_by = request.args.get('sort', 'date_desc')

        query = Invoice.query

        if search_query:
            clean_input = search_query.strip()
            clean_input_no_hash = clean_input.replace('#', '')
            search_parts = clean_input_no_hash.split()
            robust_pattern = "%" + "%".join(search_parts) + "%"

            query = query.join(Client).filter(
                or_(
                    Invoice.invoice_code.like(robust_pattern), 
                    Client.name.like(robust_pattern),
                    Client.company.like(robust_pattern) # Added Company
                )
            )

        if status_filter != 'All':
            query = query.filter(Invoice.status == status_filter)

        if sort_by == 'amount_high': query = query.order_by(Invoice.amount.desc())
        elif sort_by == 'amount_low': query = query.order_by(Invoice.amount.asc())
        elif sort_by == 'date_asc': query = query.order_by(Invoice.date_created.asc())
        else: query = query.order_by(Invoice.date_created.desc())

        invoices_pagination = query.paginate(page=page, per_page=10, error_out=False)
        return render_template('invoices.html', invoices=invoices_pagination)
    except Exception as e:
        print(traceback.format_exc())
        return render_template('error.html', error_message="Could not load invoices.")

@app.route('/invoices/create/<int:order_id>', methods=['GET', 'POST'])
@operator_required
def create_invoice(order_id):
    try:
        order = Order.query.get_or_404(order_id)
        if request.method == 'POST':
            try:
                attempts = 0
                while attempts < 10:
                    new_code = f"INV-{datetime.now().strftime('%Y%m%d')}-{random.randint(100,999)}"
                    if not Invoice.query.filter_by(invoice_code=new_code).first(): break
                    attempts += 1
                
                if attempts >= 10:
                    flash("System busy: Could not generate unique invoice ID. Try again.")
                    return redirect(url_for('invoices'))

                new_invoice = Invoice(
                    invoice_code=new_code, 
                    order_id=order.id, 
                    client_id=order.client_id, 
                    amount=order.amount, 
                    status='Sent', 
                    date_due=datetime.utcnow() + timedelta(days=30)
                )
                db.session.add(new_invoice)
                order.status = 'Invoiced'
                db.session.commit()
                log_action('System', 'AI-Invoice-Bot', 'Invoice Generated', 'Invoice', new_code, 'Success', f'Auto-generated invoice for Order {order.order_code}')
                flash(f'Invoice {new_code} generated successfully!')
                return redirect(url_for('invoices'))
            except Exception as e:
                db.session.rollback()
                flash(f"Database Error: {str(e)}", "danger")
                return redirect(url_for('error_page'))
        return render_template('create_invoice.html', order=order)
    except Exception as e:
        return redirect(url_for('error_page'))

@app.route('/invoices/view/<int:invoice_id>')
def view_invoice(invoice_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    try:
        invoice = Invoice.query.get_or_404(invoice_id)
        return render_template('view_invoice.html', invoice=invoice)
    except:
        return render_template('error.html', error_message="Invoice not found or invalid ID.")

# --- NEW: INVOICE DOWNLOAD LOGGER ---
@app.route('/log_invoice_download/<int:invoice_id>', methods=['POST'])
def log_invoice_download(invoice_id):
    if 'user_id' not in session: return "Unauthorized", 401
    try:
        invoice = Invoice.query.get(invoice_id)
        if invoice:
            user = User.query.get(session['user_id'])
            log_action('User', user.username, 'Invoice Downloaded', 'Invoice', invoice.invoice_code, 'Success', f'Downloaded invoice {invoice.invoice_code}')
        return "Logged", 200
    except: return "Error", 500

@app.route('/invoices/edit/<int:invoice_id>', methods=['GET', 'POST'])
@admin_required
def edit_invoice(invoice_id):
    try:
        invoice = Invoice.query.get_or_404(invoice_id)
        if request.method == 'POST':
            try:
                try:
                    new_amount = float(request.form['amount'])
                except ValueError:
                    flash("Error: Amount must be a number.", "danger")
                    return redirect(url_for('edit_invoice', invoice_id=invoice.id))

                new_status = request.form['status']
                
                try:
                    new_issue_date = datetime.strptime(request.form['date_created'], '%Y-%m-%d')
                    new_due_date = datetime.strptime(request.form['date_due'], '%Y-%m-%d')
                except ValueError:
                    flash("Error: Invalid date format.", "danger")
                    return redirect(url_for('edit_invoice', invoice_id=invoice.id))
                
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
                flash(f"Save failed: {str(e)}", "danger")
                return redirect(url_for('error_page'))
        return render_template('edit_invoice.html', invoice=invoice)
    except Exception:
        return render_template('error.html', error_message="Invoice could not be loaded.")

@app.route('/invoices/delete/<int:invoice_id>', methods=['POST'])
@admin_required
def delete_invoice(invoice_id):
    try:
        invoice = Invoice.query.get_or_404(invoice_id)
        if invoice.order: invoice.order.status = 'Pending'
        db.session.delete(invoice)
        db.session.commit()
        log_action('SuperAdmin', session.get('username'), 'Invoice Deleted', 'Invoice', invoice.invoice_code, 'Success', "Deleted invoice")
        flash('Invoice deleted successfully.')
        return redirect(url_for('invoices'))
    except Exception as e:
        db.session.rollback()
        flash(f"Delete failed: {str(e)}", "danger")
        return redirect(url_for('error_page'))

@app.route('/update_targets', methods=['POST'])
@admin_required
def update_targets():
    try:
        new_targets = []
        months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
        for m in months:
            val_str = request.form.get(f'target_{m}', '0')
            val_str = val_str.lower().replace(',', '')
            if 'k' in val_str:
                val = float(val_str.replace('k', '')) * 1000
            elif 'm' in val_str:
                val = float(val_str.replace('m', '')) * 1000000
            else:
                val = float(val_str)
            new_targets.append(val)
        
        save_sales_targets(new_targets)
        log_action('SuperAdmin', session.get('username'), 'Updated Targets', 'System', 'N/A', 'Success', 'Updated monthly sales targets')
        flash('Sales targets updated successfully.', 'success')
    except Exception as e:
        flash(f'Error updating targets: {str(e)}', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    try:
        user = User.query.get(session['user_id'])
        if user and user.must_change_password: return redirect(url_for('change_password'))
    except:
        pass 

    try:
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
            
        chart_invoice_target = get_sales_targets()

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
    
    except Exception as e:
        print(f"CRITICAL DASHBOARD ERROR: {e}")
        traceback.print_exc()
        flash("Dashboard loaded in safe mode due to data error.", "warning")
        
        total_orders=0; order_growth=0; total_sales=0; sales_growth=0
        products_sold=0; product_growth=0; new_customers=0; customer_growth=0
        ytd_sales=0; ytd_sales_growth=0; ytd_count=0; ytd_count_growth=0
        mtd_sales=0; mtd_sales_diff=0; mtd_count=0; mtd_count_diff=0
        chart_invoice_months=[]; chart_invoice_reality=[]; chart_invoice_target=[]
        chart_orders_ytd_pct=[0,1]; chart_orders_mtd_pct=[0,1]
        top_clients_progress=[]; chart_vol_service_labels=[]; chart_vol_data=[]; chart_service_data=[]

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
    try:
        page = request.args.get('page', 1, type=int)
        search_q = request.args.get('q', '')
        action_filter = request.args.get('action_type', '')
        
        query = AuditLog.query
        
        if search_q:
            clean_input = search_q.strip()
            clean_input_no_hash = clean_input.replace('#', '')
            search_parts = clean_input_no_hash.split()
            robust_pattern = "%" + "%".join(search_parts) + "%"

            query = query.filter(
                or_(
                    AuditLog.description.like(robust_pattern),
                    AuditLog.action.like(robust_pattern),
                    AuditLog.actor_id.like(robust_pattern),
                    AuditLog.actor_type.like(robust_pattern),
                    AuditLog.entity_id.like(robust_pattern),
                    AuditLog.entity_type.like(robust_pattern),
                    AuditLog.status.like(robust_pattern),
                    func.cast(AuditLog.timestamp, db.String).like(f"%{clean_input}%")
                )
            )
            
        if action_filter and action_filter != 'All':
            query = query.filter(AuditLog.action == action_filter)
            
        logs_pagination = query.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=10, error_out=False)
        unique_actions = [r.action for r in db.session.query(AuditLog.action).distinct()]
        return render_template('audit_log.html', logs=logs_pagination, unique_actions=unique_actions)
    except Exception as e:
        print(traceback.format_exc()) 
        return render_template('error.html', error_message="Audit Log Unavailable.")

@app.route('/audit/view/<int:log_id>')
def audit_details(log_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    try:
        log = AuditLog.query.get_or_404(log_id)
        return render_template('audit_details.html', log=log)
    except:
        return render_template('error.html', error_message="Log entry not found.")

@app.route('/admin/panel')
@admin_required
def admin_panel():
    try:
        search_q = request.args.get('q', '')
        query = User.query
        if search_q: query = query.filter(or_(User.custom_id.like(f"%{search_q}%"), User.username.like(f"%{search_q}%")))
        users = query.all()
        
        settings = get_system_settings()
        show_passwords = settings.get('show_passwords', False)
        
        return render_template('admin_panel.html', users=users, show_passwords=show_passwords)
    except Exception as e:
        return render_template('error.html', error_message="Admin Panel Error.")

@app.route('/admin/create', methods=['GET', 'POST'])
@admin_required
def create_admin():
    if request.method == 'POST':
        try:
            if User.query.filter_by(username=request.form['username']).first():
                flash('Username already exists.')
                return redirect(url_for('create_admin'))
            count = User.query.count() + 1
            
            attempts = 0
            while attempts < 5:
                custom_id = f"USR-{datetime.now().year}-{count:03d}"
                if not User.query.filter_by(custom_id=custom_id).first(): break
                count += 1
                attempts += 1

            new_user = User(
                custom_id=custom_id,
                username=request.form['username'],
                password=request.form['password'],
                role=request.form['role'],
                must_change_password=True
            )
            db.session.add(new_user)
            db.session.commit()
            log_action('SuperAdmin', session.get('username'), 'Account Created', 'User', new_user.custom_id, 'Success', f'Created new {new_user.role} user: {new_user.username}')
            return redirect(url_for('admin_panel'))
        except Exception as e:
            db.session.rollback()
            flash(f"Creation failed: {str(e)}", "danger")
            
    return render_template('admin_create.html')

@app.route('/admin/edit/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_admin(user_id):
    try:
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
            user.role = request.form['role']
            db.session.commit()
            log_action('SuperAdmin', g.user.username, 'Authority Changed', 'User', user.custom_id, 'Success', f'Changed role from {old_role} to {user.role}')
            flash(f'User {user.username} updated to {user.role}.', 'success')
            return redirect(url_for('admin_panel'))
            
        return render_template('admin_edit.html', user=user)
    except:
        return redirect(url_for('error_page'))

@app.route('/admin/reset_password/<int:user_id>', methods=['POST'])
@admin_required
def reset_password(user_id):
    try:
        user = User.query.get_or_404(user_id)
        temp_pass = request.form['temp_password']
        new_username = request.form.get('new_username')
        new_email = request.form.get('new_email') 
        
        if new_username: user.username = new_username
        
        old_email = user.email 
        if new_email and new_email.strip(): user.email = new_email.strip()
        
        user.password = temp_pass
        user.must_change_password = True
        
        # --- AUTO-UNSUSPEND LOGIC ---
        extra_log_note = ""
        if user.is_suspended:
            user.is_suspended = False
            user.failed_attempts = 0 # Reset counter
            extra_log_note = " (Auto-unsuspended)"
        else:
            user.failed_attempts = 0 # Just reset counter
        
        target_email = user.email
        db.session.commit()
        
        email_status = False
        email_msg = "No email on file."
        
        if target_email:
            success, msg = send_temp_password_email(target_email, temp_pass)
            email_status = success
            email_msg = msg
        
        if email_status:
            flash(f'Reset successful. Email sent to {target_email}.', 'success')
            log_type = 'Success'
        else:
            if "Simulated" in email_msg:
                flash(f'Simulated Reset: Password printed to server console.', 'warning')
            else:
                flash(f'Reset successful, but EMAIL FAILED: {email_msg} (Check Console for Password)', 'warning')
            log_type = 'Warning'

        change_note = ""
        if old_email and old_email != user.email:
            change_note = f" (Email changed from {old_email} to {user.email})"

        log_action('SuperAdmin', session.get('username'), 'Credentials Updated', 'User', user.custom_id, log_type, f'Reset password{extra_log_note}. Email: {email_msg}{change_note}')
        return redirect(url_for('admin_panel'))
    except Exception as e:
        db.session.rollback()
        flash(f"Reset failed: {str(e)}", "danger")
        return redirect(url_for('admin_panel'))

@app.route('/admin/suspend/<int:user_id>', methods=['POST'])
@admin_required
def suspend_admin(user_id):
    try:
        user = User.query.get(user_id)
        user.is_suspended = not user.is_suspended
        
        if not user.is_suspended:
            user.failed_attempts = 0
            
        db.session.commit()
        action_type = "Account Suspended" if user.is_suspended else "Account Reactivated"
        log_action('SuperAdmin', session.get('username'), action_type, 'User', user.custom_id, 'Warning', f'User {user.username} status toggled.')
        return redirect(url_for('admin_panel'))
    except:
        db.session.rollback()
        return redirect(url_for('error_page'))

@app.route('/admin/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_admin(user_id):
    try:
        user = User.query.get(user_id)
        if user:
            u_name = user.username
            u_id = user.custom_id
            db.session.delete(user)
            db.session.commit()
            log_action('SuperAdmin', session.get('username'), 'Account Deleted', 'User', u_id, 'Danger', f'Deleted user: {u_name}')
        return redirect(url_for('admin_panel'))
    except:
        db.session.rollback()
        return redirect(url_for('error_page'))

@app.route('/admin/danger_zone', methods=['GET', 'POST'])
@admin_required
def danger_zone():
    current_skipped = get_total_skipped_days()
    settings = get_system_settings()
    show_passwords = settings.get('show_passwords', False)
    email_required = settings.get('email_required', True)
    
    if request.method == 'POST':
        action = request.form.get('action')
        try:
            if action == 'toggle_passwords':
                new_state = not show_passwords
                update_system_setting('show_passwords', new_state)
                log_action('SuperAdmin', session.get('username'), 'Security Policy Change', 'System', 'ALL', 'Warning', f'Admin password visibility set to {new_state}')
                flash(f'Password visibility turned {"ON" if new_state else "OFF"}.', 'warning' if new_state else 'success')
                return redirect(url_for('danger_zone'))
            
            elif action == 'toggle_email_req':
                new_state = not email_required
                update_system_setting('email_required', new_state)
                status_msg = "Enabled" if new_state else "Disabled"
                log_action('SuperAdmin', session.get('username'), 'Policy Change', 'System', 'ALL', 'Warning', f'Mandatory email requirement {status_msg}')
                flash(f'Mandatory email requirement {status_msg}.', 'success')
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
        except Exception as e:
            flash(f"System Error: {str(e)}", "danger")

        return redirect(url_for('dashboard'))
            
    return render_template('danger_zone.html', days_skipped=current_skipped, show_passwords=show_passwords, email_required=email_required)

# --- REALISTIC FASHION BULK DATA GENERATOR ---
@app.route('/generate_bulk_data')
@operator_required
def generate_bulk_data():
    try:
        clients_data = [
            {"name": "Vogue Styles Boutique", "email": "orders@voguestyles.com", "company": "Vogue Styles"},
            {"name": "Urban Trends Retail", "email": "procurement@urbantrends.sg", "company": "Urban Trends Retail"},
            {"name": "Chic Avenue", "email": "hello@chicavenue.com", "company": "Chic Avenue"},
            {"name": "The Fashion Loft", "email": "inventory@fashionloft.co", "company": "The Fashion Loft"},
            {"name": "Runway Ready", "email": "buying@runwayready.com", "company": "Runway Ready"},
            {"name": "Modern Look Dept Store", "email": "accounts@modernlook.com", "company": "Modern Look Dept Store"},
            {"name": "Velvet & Silk", "email": "admin@velvetsilk.com", "company": "Velvet & Silk"},
            {"name": "Minimalist Wardrobe", "email": "supply@minimalist.io", "company": "Minimalist Wardrobe"}
        ]
        
        product_catalog = [
            ("Premium Cotton Crewneck T-Shirt", 18.50, 28.00),
            ("Oversized Graphic Hoodie", 45.00, 75.00),
            ("Silk Button-Up Blouse", 85.00, 120.00),
            ("Ribbed Knit Sweater", 55.00, 89.00),
            ("Classic Polo Shirt", 35.00, 55.00),
            ("Slim Fit Denim Jeans", 60.00, 110.00),
            ("High-Waisted Linen Trousers", 50.00, 85.00),
            ("Pleated Midi Skirt", 40.00, 65.00),
            ("Athleisure Joggers", 35.00, 60.00),
            ("Floral Summer Dress", 65.00, 110.00),
            ("Evening Cocktail Gown", 150.00, 320.00),
            ("Tailored Formal Blazer", 120.00, 250.00),
            ("Denim Jacket (Vintage Wash)", 70.00, 110.00),
            ("Trench Coat", 180.00, 300.00),
            ("Leather Belt", 25.00, 45.00),
            ("Designer Sunglasses", 110.00, 210.00),
            ("Canvas Tote Bag", 15.00, 30.00),
            ("Leather Crossbody Bag", 130.00, 280.00),
            ("White Leather Sneakers", 80.00, 140.00),
            ("Ankle Boots", 90.00, 160.00)
        ]

        db_clients = []
        for c_data in clients_data:
            client = Client.query.filter_by(name=c_data['name']).first()
            if not client:
                client = Client(name=c_data['name'], email=c_data['email'], company=c_data['company'])
                db.session.add(client)
            db_clients.append(client)
        db.session.commit()

        for i in range(25):
            client = random.choice(db_clients)
            days_ago = random.randint(0, 90)
            order_date = datetime.utcnow() - timedelta(days=days_ago)

            is_multi_item = random.random() > 0.3
            num_items = random.randint(2, 6) if is_multi_item else 1
            selected_products = random.sample(product_catalog, num_items)
            
            attempts = 0
            while attempts < 10:
                order_code = f"ORD-{order_date.strftime('%Y%m%d')}-{random.randint(1000,9999)}"
                if not Order.query.filter_by(order_code=order_code).first(): break
                attempts += 1

            new_order = Order(
                order_code=order_code,
                client_id=client.id,
                description=f"Fashion Stock Order for {client.company}",
                amount=0, 
                date_placed=order_date,
                status=random.choice(['Pending', 'Invoiced', 'Invoiced', 'Invoiced']) 
            )
            db.session.add(new_order)
            db.session.flush() 

            running_subtotal = 0.0

            for prod_name, min_p, max_p in selected_products:
                qty = random.choices([1, 2, 5, 10, 15, 20], weights=[10, 20, 30, 20, 10, 10])[0]
                base_price = random.uniform(min_p, max_p)
                unit_price = round(base_price, 2)
                line_total = round(unit_price * qty, 2)
                running_subtotal += line_total

                item = OrderItem(
                    order_id=new_order.id,
                    item_name=prod_name,
                    quantity=qty,
                    unit_price=unit_price,
                    total_price=line_total
                )
                db.session.add(item)

            shipping_cost = round(random.uniform(15.00, 45.00), 2)
            if running_subtotal > 1500: shipping_cost = round(random.uniform(60.00, 150.00), 2)
            running_subtotal += shipping_cost
            
            shipping_item = OrderItem(
                order_id=new_order.id,
                item_name="Shipping & Handling (Standard)",
                quantity=1,
                unit_price=shipping_cost,
                total_price=shipping_cost
            )
            db.session.add(shipping_item)

            gst_amount = round(running_subtotal * 0.09, 2)
            gst_item = OrderItem(
                order_id=new_order.id,
                item_name="GST (9%)",
                quantity=1,
                unit_price=gst_amount,
                total_price=gst_amount
            )
            db.session.add(gst_item)

            final_total = running_subtotal + gst_amount
            new_order.amount = round(final_total, 2)

            if new_order.status == 'Invoiced':
                inv_code = f"INV-{order_date.strftime('%Y%m%d')}-{random.randint(100,999)}"
                inv_status = 'Pending'
                days_diff = (datetime.utcnow() - order_date).days
                if days_diff > 35: inv_status = random.choice(['Paid', 'Paid', 'Overdue'])
                elif days_diff < 5: inv_status = 'Sent'
                else: inv_status = random.choice(['Paid', 'Pending'])

                invoice = Invoice(
                    invoice_code=inv_code,
                    order_id=new_order.id,
                    client_id=client.id,
                    amount=new_order.amount,
                    status=inv_status,
                    date_created=order_date,
                    date_due=order_date + timedelta(days=30)
                )
                db.session.add(invoice)

        db.session.commit()
        log_action('System', 'DataGen', 'Bulk Generation', 'System', 'N/A', 'Success', 'Generated 25 realistic fashion orders.')
        flash("Success! Generated 25 fashion orders with GST (9%) and Shipping.", "success")
        return redirect(url_for('dashboard'))

    except Exception as e:
        db.session.rollback()
        print(traceback.format_exc())
        flash(f"Bulk Generation Failed: {str(e)}", "danger")
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
                # NEW: Add failsafe column if missing
                try: conn.execute(text("ALTER TABLE user ADD COLUMN failed_attempts INTEGER DEFAULT 0"))
                except: pass
        except: pass
        
        db.create_all()
        
        try:
            db.session.execute(text("UPDATE audit_log SET action = 'Account Suspended' WHERE action = 'Suspended User'"))
            db.session.execute(text("UPDATE audit_log SET action = 'Account Reactivated' WHERE action = 'Re-activated User'"))
            db.session.execute(text("UPDATE audit_log SET action = 'Account Deleted' WHERE action = 'Delete User'"))
            db.session.execute(text("UPDATE audit_log SET action = 'Authority Changed' WHERE action = 'Edit User Role'"))
            db.session.execute(text("UPDATE audit_log SET action = 'Password Changed' WHERE action = 'Password Change'"))
            db.session.commit()
        except: pass

        if not User.query.first():
            admin = User(username='admin', password='password123', role='SuperAdmin', custom_id='USR-ADMIN-001')
            db.session.add(admin)
            db.session.commit()
            
    app.run(debug=True)