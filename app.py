# ==============================================================================
# SECTION 1: IMPORTS & LIBRARIES
# ==============================================================================
from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, extract, or_, text
from sqlalchemy.pool import NullPool
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import random
import os
import json
import smtplib
import re
import traceback
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, session, g, jsonify
import google.generativeai as genai
import socket  # <--- Needed for timeout errors
from smtplib import SMTPAuthenticationError, SMTPConnectError, SMTPException

# Load environment variables
load_dotenv()

# ==============================================================================
# SECTION 2: APP CONFIGURATION & SETUP
# ==============================================================================
# 1. Initialize Flask App (Single Instance)
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your_secret_key_here')

# 2. Database Configuration
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'business_data.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'poolclass': NullPool}

# 3. Upload Configuration
UPLOAD_FOLDER = os.path.join(basedir, 'static', 'profile_pics')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ---> ADD THESE 3 LINES FOR PRODUCTS <---
PRODUCT_UPLOAD_FOLDER = os.path.join(basedir, 'static', 'product_images')
app.config['PRODUCT_UPLOAD_FOLDER'] = PRODUCT_UPLOAD_FOLDER
os.makedirs(PRODUCT_UPLOAD_FOLDER, exist_ok=True)

# 4. Email Configuration
app.config['SMTP_SERVER'] = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
app.config['SMTP_EMAIL'] = os.environ.get('SMTP_EMAIL')
app.config['SMTP_PASSWORD'] = os.environ.get('SMTP_PASSWORD')

# ==============================================================================
# SECTION 3: OAUTH SETUP (GOOGLE & DISCORD)
# ==============================================================================
# Load Keys
app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')
app.config['DISCORD_CLIENT_ID'] = os.environ.get('DISCORD_CLIENT_ID')
app.config['DISCORD_CLIENT_SECRET'] = os.environ.get('DISCORD_CLIENT_SECRET')

# Debug Print
print(f"DEBUG: Found Google ID? {'YES' if app.config['GOOGLE_CLIENT_ID'] else 'NO'}")
print(f"DEBUG: Found Discord ID? {'YES' if app.config['DISCORD_CLIENT_ID'] else 'NO'}")

# Initialize OAuth
try:
    from authlib.integrations.flask_client import OAuth
    oauth = OAuth(app)
    authlib_installed = True
except ImportError:
    authlib_installed = False
    print("Warning: Authlib not installed. Social Login will be disabled.")

if authlib_installed:
    # --- Register Google ---
    google = oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'}
    )

    # --- Register Discord (NEW) ---
    discord = oauth.register(
        name='discord',
        client_id=app.config['DISCORD_CLIENT_ID'],
        client_secret=app.config['DISCORD_CLIENT_SECRET'],
        authorize_url='https://discord.com/api/oauth2/authorize',
        access_token_url='https://discord.com/api/oauth2/token',
        api_base_url='https://discord.com/api/',
        client_kwargs={'scope': 'identify email'}
    )

# Initialize Database
db = SQLAlchemy(app)
MAX_LOGIN_ATTEMPTS = 5

# ==============================================================================
# SECTION 3: FILE HANDLING & HELPERS
# ==============================================================================
SETTINGS_FILE = os.path.join(basedir, 'system_settings.json')
TARGETS_FILE = os.path.join(basedir, 'sales_targets.json')
OFFSET_FILE = os.path.join(basedir, 'time_offset.json')

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

def get_sales_targets():
    default_targets = [20000] * 12
    if not os.path.exists(TARGETS_FILE): return default_targets
    try:
        with open(TARGETS_FILE, 'r') as f:
            data = json.load(f)
            return data.get('targets', default_targets)
    except: return default_targets

def save_sales_targets(targets):
    with open(TARGETS_FILE, 'w') as f: json.dump({'targets': targets}, f)

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

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.template_filter('smart_pagination')
def smart_pagination_filter(pagination):
    if not pagination: return []
    iterator = pagination.iter_pages(left_edge=1, right_edge=1, left_current=2, right_current=2)
    result = []
    last_page = 0
    gap_marker = False
    if iterator:
        for num in iterator:
            if num is None: gap_marker = True
            else:
                if gap_marker:
                    midpoint = (last_page + num) // 2
                    result.append({'type': 'gap', 'page': midpoint})
                    gap_marker = False
                result.append({'type': 'page', 'page': num})
                last_page = num
    return result

def format_k(value):
    try:
        if value is None: return "0"
        if value >= 1000000: return f"{value/1000000:.1f}M"
        if value >= 1000: return f"{value/1000:.1f}k"
        return str(value)
    except: return "Err"

def calculate_cart_totals(cart):
    if not cart: return {'subtotal': 0, 'shipping': 0, 'gst': 0, 'grand_total': 0}
    subtotal = sum(item['price'] * item['qty'] for item in cart.values())
    shipping = 0 if subtotal >= 150 else 15.00
    gst = (subtotal + shipping) * 0.09
    grand_total = subtotal + shipping + gst
    return {'subtotal': subtotal, 'shipping': shipping, 'gst': gst, 'grand_total': grand_total}

def send_otp_email(user_email, otp_code):
    sender_email = app.config.get('SMTP_EMAIL')
    sender_password = app.config.get('SMTP_PASSWORD')
    smtp_server = app.config.get('SMTP_SERVER')
    
    # 1. LOG TO CONSOLE (Always reliable for Dev)
    print(f"\n[SYSTEM OTP] To: {user_email} | Code: {otp_code}\n")
    
    # 2. Check Config
    if not sender_email or not sender_password:
        return False # Indicate email wasn't sent (will trigger flash fallback)
        
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = user_email
    msg['Subject'] = f"{otp_code} is your Shop.co code"
    body = f"""
    <div style="font-family: Arial; padding: 20px; border: 1px solid #eee;">
        <h2>Verify your account</h2>
        <p>Use the code below to complete your setup.</p>
        <h1 style="letter-spacing: 5px; background: #f4f4f4; padding: 10px; display: inline-block;">{otp_code}</h1>
    </div>
    """
    msg.attach(MIMEText(body, 'html'))
    try:
        server = smtplib.SMTP(smtp_server, 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, user_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"Email Error: {e}")
        return False
    
def send_temp_password_email(user_email, temp_password):
    # 1. Load Credentials (Exactly like send_otp_email)
    sender_email = app.config.get('SMTP_EMAIL')
    sender_password = app.config.get('SMTP_PASSWORD')
    smtp_server = app.config.get('SMTP_SERVER')

    # 2. Check for Missing Config (Dev Mode)
    if not sender_email or not sender_password: 
        print(f"\n[DEV MODE - RESET] To: {user_email} | TempPW: {temp_password}\n")
        return True

    # 3. Construct Email (HTML Format)
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = user_email
    msg['Subject'] = "Security Update: Login Credentials Changed"
    
    body = f"""
    <div style="font-family: Arial; padding: 20px; border: 1px solid #eee;">
        <h2>Credentials Updated</h2>
        <p>An administrator has manually reset your password.</p>
        <p><strong>Your Temporary Password:</strong></p>
        <h1 style="letter-spacing: 2px; background: #f4f4f4; padding: 10px; display: inline-block;">{temp_password}</h1>
        <p>Please login and change this password immediately.</p>
    </div>
    """
    msg.attach(MIMEText(body, 'html'))

    # 4. Send Email (Standard Logic)
    try:
        server = smtplib.SMTP(smtp_server, 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, user_email, msg.as_string())
        server.quit()
        print(f"\n[SUCCESS] Password email sent to {user_email}\n")
        return True
    except Exception as e:
        print(f"\n[ERROR] Failed to send password email: {e}\n")
        return False

@app.before_request
def load_user():
    g.user = None
    if 'user_id' in session: 
        try: 
            user = User.query.get(session['user_id'])
            if user:
                if user.is_suspended:
                    session.clear() # Force Logout
                    flash("Your account has been suspended. Please contact support.", "danger")
                else:
                    g.user = user
            else:
                session.clear()
        except: session.clear()

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.user or g.user.role == 'Customer':
            flash("Access Denied.", "danger")
            return redirect(url_for('store_home'))
        return f(*args, **kwargs)
    return decorated_function

def operator_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.user or g.user.role == 'Customer':
            flash("Access Denied.", "danger")
            return redirect(url_for('store_home'))
        return f(*args, **kwargs)
    return decorated_function

# ==============================================================================
# SECTION 4: DATABASE MODELS
# ==============================================================================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    custom_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False) 
    
    # CRITICAL: This separates Admins from Customers
    # Values: 'Customer' vs 'SuperAdmin', 'Manager', 'Staff'
    role = db.Column(db.String(20), default='Staff') 
    # In app.py - class User
    profile_image = db.Column(db.String(200), default='default.jpg') # Added default='default.jpg'
    email = db.Column(db.String(120), unique=True, nullable=True)
    
    # --- CUSTOMER DETAILS ---
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    phone = db.Column(db.String(20))
    gender = db.Column(db.String(20))
    auth_provider = db.Column(db.String(20), default='local') 
    profile_image = db.Column(db.String(200)) 
    
    # --- SECURITY ---
    otp = db.Column(db.String(6))
    otp_expiry = db.Column(db.DateTime)
    new_email_temp = db.Column(db.String(120)) 
    new_password_temp = db.Column(db.String(100)) 
    is_verified = db.Column(db.Boolean, default=False)
    
    is_suspended = db.Column(db.Boolean, default=False)
    must_change_password = db.Column(db.Boolean, default=False)
    failed_attempts = db.Column(db.Integer, default=0)
    
    payment_methods = db.relationship('PaymentMethod', backref='user', lazy=True)

class PaymentMethod(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    cardholder_name = db.Column(db.String(100)) # Added this field
    card_type = db.Column(db.String(20)) 
    last4 = db.Column(db.String(4))
    expiry = db.Column(db.String(7))

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

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50))
    image_url = db.Column(db.Text) 
    description = db.Column(db.String(500))
    stock = db.Column(db.Integer, default=100)
    sales_count = db.Column(db.Integer, default=0)
    sizes = db.Column(db.String(200)) 
    colors = db.Column(db.String(200))

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False) # Changed to product_id
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    title = db.Column(db.String(100)) # Added title field
    comment = db.Column(db.Text)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='reviews')
    product = db.relationship('Product', backref='reviews')

class PasswordHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# ==============================================================================
# SECTION 5: HELPER FUNCTIONS
# ==============================================================================
def is_password_strong(password):
    """
    Requirements:
    - At least 8 characters
    - Uppercase letter
    - Lowercase letter
    - Number
    - Special Character (Symbol)
    """
    if len(password) < 8: return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password): return False, "Password must contain an uppercase letter."
    if not re.search(r"[a-z]", password): return False, "Password must contain a lowercase letter."
    if not re.search(r"\d", password): return False, "Password must contain a number."
    if not re.search(r"[\W_]", password): return False, "Password must contain a symbol (e.g. !@#$)."
    return True, "Valid"

def check_invoice_expiry():
    """Checks for pending invoices older than 7 days and marks them expired."""
    try:
        # Calculate date 7 days ago
        limit = datetime.utcnow() - timedelta(days=7)
        
        # Find pending invoices older than limit
        expired_invoices = Invoice.query.filter(Invoice.status == 'Pending', Invoice.date_created < limit).all()
        
        if expired_invoices:
            count = 0
            for inv in expired_invoices:
                inv.status = 'Expired'
                # Attempt to restore stock (Match by Name since Product ID isn't in OrderItem)
                if inv.order:
                    for item in inv.order.items:
                        prod = Product.query.filter_by(name=item.item_name).first()
                        if prod:
                            prod.stock += item.quantity
                            prod.sales_count -= item.quantity
                count += 1
            
            db.session.commit()
            print(f"[SYSTEM] Expired {count} old pending invoices.")
    except Exception as e:
        print(f"[SYSTEM] Expiry Check Failed: {e}")

def log_action(actor_type, actor_id, action, entity_type, entity_id, status, description):
    try:
        log = AuditLog(actor_type=actor_type, actor_id=actor_id, action=action, entity_type=entity_type, entity_id=entity_id, status=status, description=description)
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Logging Failed: {e}")
def seed_products():
    """Seeds the DB with premium products containing multiple images and variants."""
    if Product.query.count() == 0:
        print("Seeding Database with Premium Variants...")
        products = [
            Product(
                name="90s Vintage Baggy Jeans", price=65.00, category="Bottoms", 
                image_url="https://images.unsplash.com/photo-1541099649105-f69ad21f3246?q=80&w=1000|https://images.unsplash.com/photo-1542272617-0858607c22f7?q=80&w=1000|https://images.unsplash.com/photo-1584370848010-d7d637167ebf?q=80&w=1000",
                description="Heavyweight denim with a relaxed 90s cut.", stock=50, 
                sizes="28,30,32,34,36", colors="Washed Blue,Vintage Black,Grey"
            ),
            Product(
                name="Essential Oversized Hoodie", price=85.00, category="Tops", 
                image_url="https://images.unsplash.com/photo-1556905055-8f358a7a47b2?q=80&w=1000|https://images.unsplash.com/photo-1620799140408-ed5341cd2431?q=80&w=1000",
                description="400gsm french terry cotton. Drop shoulder fit.", stock=40, 
                sizes="S,M,L,XL,XXL", colors="Jet Black,Heather Grey,Cream"
            ),
            Product(
                name="Street Runner V2", price=120.00, category="Shoes", 
                image_url="https://images.unsplash.com/photo-1552346154-21d32810aba3?q=80&w=1000|https://images.unsplash.com/photo-1560769629-975ec94e6a86?q=80&w=1000",
                description="Chunky silhouette with reactive foam cushioning.", stock=20, 
                sizes="US 7,US 8,US 9,US 10,US 11", colors="White/Red,Triple Black"
            ),
            Product(
                name="Minimalist Silver Chain", price=45.00, category="Accessories", 
                image_url="https://images.unsplash.com/photo-1611085583191-a3b181a88401?q=80&w=1000",
                description="Sterling silver curb chain. 20 inch length.", stock=50, 
                sizes="", colors=""
            )
        ]
        db.session.add_all(products)
        db.session.commit()
        print("Premium Products Added!")

# app.py - Add to Section 5

def check_incomplete_signup():
    """Checks if the logged-in user has completed their account setup."""
    if not g.user:
        return None # Not logged in, let other checks handle it
        
    # 1. Check if Email is Verified
    if not g.user.is_verified:
        # If they are logged in but not verified, send them to verify page
        # We need to set the session variable so verify page knows who they are
        session['pending_user_id'] = g.user.id
        session['auth_email'] = g.user.email
        flash("Please verify your email address to continue.", "warning")
        return redirect(url_for('store_verify'))

    # 2. Check if Social Login Setup is Complete (Password Placeholder)
    placeholders = [
        "GOOGLE_OAUTH_USER", "DISCORD_OAUTH_USER", 
        "FACEBOOK_OAUTH_USER", "MICROSOFT_OAUTH_USER", 
        "GITHUB_OAUTH_USER"
    ]
    
    if g.user.password in placeholders:
        flash("Please complete your account setup to continue.", "warning")
        return redirect(url_for('store_setup_password'))
        
    return None
# ==============================================================================
# SECTION 6: ROUTES (STORE & AUTH)
# ==============================================================================
@app.context_processor
def inject_cart():
    cart = session.get('cart', {})
    cart_count = sum(item['qty'] for item in cart.values())
    return dict(cart_count=cart_count)

@app.route('/')
def store_home():
    new_arrivals = Product.query.order_by(Product.id.desc()).limit(4).all()
    top_selling = Product.query.order_by(Product.sales_count.desc()).limit(4).all()
    return render_template('store_home.html', new_arrivals=new_arrivals, top_selling=top_selling)

@app.route('/shop')
def store_shop():
    search_query = request.args.get('q', '')
    category_filter = request.args.get('category', 'All') 
    sort_by = request.args.get('sort', 'newest')
    min_price = request.args.get('min_price', type=float)
    max_price = request.args.get('max_price', type=float)
    selected_sizes = request.args.getlist('size')
    page = request.args.get('page', 1, type=int)
    
    query = Product.query
    if search_query: query = query.filter(Product.name.ilike(f'%{search_query}%'))
    if category_filter != 'All': query = query.filter(Product.category == category_filter)
    if min_price is not None: query = query.filter(Product.price >= min_price)
    if max_price is not None: query = query.filter(Product.price <= max_price)
    if selected_sizes:
        size_conditions = [Product.sizes.ilike(f'%{size}%') for size in selected_sizes]
        query = query.filter(or_(*size_conditions))

    if sort_by == 'price_low': query = query.order_by(Product.price.asc())
    elif sort_by == 'price_high': query = query.order_by(Product.price.desc())
    elif sort_by == 'popularity': query = query.order_by(Product.sales_count.desc())
    else: query = query.order_by(Product.id.desc())

    pagination = query.paginate(page=page, per_page=12, error_out=False)
    price_stats = db.session.query(func.min(Product.price), func.max(Product.price)).first()
    db_min_price = int(price_stats[0]) if price_stats[0] else 0
    db_max_price = int(price_stats[1]) if price_stats[1] else 500

    return render_template('store_shop.html', products=pagination.items, pagination=pagination,
        all_categories=['Casual', 'Formal', 'Shoes', 'Accessories'], current_cat=category_filter, 
        current_sort=sort_by, search_query=search_query, current_min_price=min_price,
        current_max_price=max_price, selected_sizes=selected_sizes, db_min_price=db_min_price, db_max_price=db_max_price)

# --- NEW ROUTES FOR ABOUT & CONTACT ---

@app.route('/about')
def store_about():
    return render_template('store_about.html')

@app.route('/contact', methods=['GET', 'POST'])
def store_contact():
    if request.method == 'POST':
        # Capture form data (for now, we just print it)
        name = request.form.get('name')
        subject = request.form.get('subject')
        
        # In a real app, you would send an email here
        print(f"\n[CONTACT FORM] From: {name} | Subject: {subject}\n")
        
        flash("Message sent! We'll get back to you shortly.", "success")
        return redirect(url_for('store_contact'))
        
    return render_template('store_contact.html')

# --- AI CHATBOT ROUTE ---
# --- AI CHATBOT ROUTE ---
# --- AI CHATBOT ROUTE ---
@app.route('/api/chat', methods=['POST'])
def chat_bot():
    try:
        data = request.json
        user_msg = data.get('message')
        
        # 1. Securely Load API Key
        api_key = os.environ.get('GEMINI_API_KEY')
        if not api_key or 'PASTE_YOUR' in api_key:
            return jsonify({'status': 'error', 'reply': "System Error: AI service is currently unconfigured."})

        genai.configure(api_key=api_key)
        
        # --- 2. FETCH LIVE STORE DATA ---
        products = Product.query.limit(50).all()
        inventory_context = "\n".join([
            f"- {p.name} (Category: {p.category}): ${p.price:.2f} | Stock: {p.stock} | Sizes: {p.sizes} | Colors: {p.colors}" 
            for p in products
        ])

        # --- 3. FETCH LIVE USER DATA ---
        user_context = "Guest User (Not logged in)."
        if g.user and g.user.role == 'Customer':
            client = Client.query.filter_by(email=g.user.email).first()
            if client:
                orders = Order.query.filter_by(client_id=client.id).order_by(Order.date_placed.desc()).limit(3).all()
                if orders:
                    order_details = "\n".join([f"Order {o.order_code}: Status is {o.status}, Total ${o.amount:.2f}" for o in orders])
                    user_context = f"User Name: {g.user.first_name}.\nRecent Orders:\n{order_details}"
                else:
                    user_context = f"User Name: {g.user.first_name}. No previous orders."

        # --- 4. DYNAMIC SYSTEM INSTRUCTION ---
        system_instruction = f"""
        You are the AI Concierge for Shop.co, a high-end fashion retailer.
        Your Persona: Professional, polite, concise, and helpful. You speak with an elegant tone.
        
        Store Policies:
        - Shipping: Free worldwide shipping on orders over $150. Orders under $150 cost $15.
        - Returns: We accept returns within 30 days of purchase for unworn items.
        - Location: 88 Orchard Road, Singapore.
        - Contact: support@shop.co for complex issues.

        LIVE INVENTORY DATA:
        {inventory_context}

        CURRENT USER DATA:
        {user_context}
        
        Guidelines:
        - Keep answers short (under 3 sentences).
        - Do not list the whole inventory. Only mention products relevant to their question.
        - If they ask for order status, answer using the CURRENT USER DATA. 
        """
        
    # --- 5. GENERATE RESPONSE (FIXED MODEL NAME) ---
        # Updated to the latest stable model version
        model = genai.GenerativeModel(
            model_name='gemini-1.5-flash-latest',
            system_instruction=system_instruction
        )
        
        chat = model.start_chat(history=[])
        response = chat.send_message(user_msg)
        
        # 6. Format Output (Clean up markdown bolding for the simple HTML UI)
        reply_text = response.text.replace('**', '') 
        
        return jsonify({'status': 'success', 'reply': reply_text})
        
    except Exception as e:
        print(f"AI Chatbot Error: {str(e)}")
        if "400" in str(e) or "API key" in str(e):
            return jsonify({'status': 'error', 'reply': "Configuration Error: Invalid API Key."})
            
        return jsonify({'status': 'error', 'reply': "I apologize, but our concierge service is momentarily unavailable."})

# --- AUTHENTICATION FLOW ---
    
# --- AUTHENTICATION FLOW ---

# --- AUTH FLOW UPDATES ---

@app.route('/store/auth', methods=['GET', 'POST'])
def store_auth():
    if g.user: return redirect(url_for('store_home'))
    
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        session['auth_email'] = email 
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Separation Check
            if user.role != 'Customer':
                flash("Staff members must use the Admin Login Portal.", "warning")
                return redirect(url_for('login'))
            
            # --- NEW FLOW: Don't send OTP yet. Redirect to Options. ---
            return redirect(url_for('store_login_options'))
        else:
            # New User -> Signup
            return redirect(url_for('store_signup_details'))
            
    return render_template('store_auth.html')

@app.route('/store/login/options')
def store_login_options():
    """Step 2: User selects how they want to log in."""
    email = session.get('auth_email')
    if not email: return redirect(url_for('store_auth'))
    return render_template('store_login_options.html', email=email)

@app.route('/store/login/initiate_otp')
def store_initiate_otp():
    """Sends the OTP and redirects to verify page."""
    email = session.get('auth_email')
    if not email: return redirect(url_for('store_auth'))
    
    user = User.query.filter_by(email=email).first()
    if not user: return redirect(url_for('store_auth'))
    
    # Check Suspension
    if user.is_suspended:
        flash("Your account has been suspended.", "danger")
        return redirect(url_for('store_auth'))

    # Generate & Send OTP
    otp = f"{random.randint(100000, 999999)}"
    user.otp = otp
    user.otp_expiry = datetime.utcnow() + timedelta(minutes=10)
    db.session.commit()
    
    # Attempt to send email
    email_sent = send_otp_email(email, otp)
    
    session['pending_user_id'] = user.id
    
    if email_sent:
        flash(f"Verification code sent to {email}", "success")
    else:
        # FALLBACK for Dev Mode or SMTP Failure
        flash(f"Dev Mode: Your code is {otp}", "info")
        
    return redirect(url_for('store_verify'))

@app.route('/store/login/password', methods=['GET', 'POST'])
def store_login_password():
    if g.user: return redirect(url_for('store_home'))
    
    email = session.get('auth_email')
    if not email: return redirect(url_for('store_auth'))

    if request.method == 'POST':
        # Use email from session to ensure security/consistency
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.role == 'Customer':
            if user.is_suspended:
                flash("Your account has been suspended.", "danger")
                return redirect(url_for('store_auth'))

            if user.failed_attempts >= 5:
                flash("Account locked. Please verify via OTP to unlock.", "danger")
                return redirect(url_for('store_initiate_otp'))

            is_correct = False
            if user.password.startswith('scrypt:'):
                is_correct = check_password_hash(user.password, password)
            else:
                is_correct = (user.password == password)

            if is_correct:
                user.failed_attempts = 0
                db.session.commit()
                session['user_id'] = user.id
                flash(f"Welcome back, {user.first_name}!", "success")
                return redirect(url_for('store_home'))
            else:
                user.failed_attempts = (user.failed_attempts or 0) + 1
                db.session.commit()
                flash("Incorrect password.", "danger")
        else:
            flash("Account not found.", "warning")
            return redirect(url_for('store_auth'))
            
    return render_template('store_login.html', email=email)

@app.route('/store/forgot_password')
def store_forgot_password():
    """Step 1: User clicks Forgot Password. Set flag and send OTP."""
    flash("To reset your password, please verify your email with a code.", "info")
    session['reset_flow'] = True  # <--- Mark this session as a Password Reset attempt
    return redirect(url_for('store_initiate_otp'))

@app.route('/store/signup', methods=['GET', 'POST'])
def store_signup_details():
    email = session.get('auth_email')
    if not email: return redirect(url_for('store_auth'))
    
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        phone = request.form.get('phone')
        gender = request.form.get('gender')
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')
        
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template('store_signup.html', email=email, form_data=request.form)
            
        valid, msg = is_password_strong(password)
        if not valid:
            flash(f"Weak Password: {msg}", "danger")
            return render_template('store_signup.html', email=email, form_data=request.form)
            
        if User.query.filter_by(email=email).first():
            flash("Account already exists. Redirecting to login...", "warning")
            return redirect(url_for('store_auth'))

        try:
            # --- ID GENERATION START ---
            # Get the last user who is explicitly a Customer to continue sequence
            last_cust = User.query.filter(User.custom_id.like('CUST-%')).order_by(User.id.desc()).first()

            if last_cust and last_cust.custom_id:
                try:
                    # Extract last number (e.g. 'CUST-2026-005' -> 5)
                    last_num = int(last_cust.custom_id.split('-')[-1])
                    new_num = last_num + 1
                except (ValueError, IndexError):
                    # Fallback if ID format is broken
                    new_num = User.query.count() + 1
            else:
                # First customer ever
                new_num = 1

            custom_id = f"CUST-{datetime.now().year}-{new_num:03d}"
            # --- ID GENERATION END ---
            
            hashed_pw = generate_password_hash(password)
            
            # Generate OTP for verification
            otp = f"{random.randint(100000, 999999)}"
            
            # CREATE USER (Note: is_verified=False initially)
            new_user = User(
                custom_id=custom_id,
                username=email, 
                email=email, 
                password=hashed_pw, 
                first_name=first_name, 
                last_name=last_name, 
                phone=phone, 
                gender=gender,
                role='Customer',        # <--- FORCE CUSTOMER ROLE
                profile_image='default.jpg',  # <--- ADDED DEFAULT IMAGE
                auth_provider='local', 
                otp=otp,
                otp_expiry=datetime.utcnow() + timedelta(minutes=10),
                is_verified=False       # <--- MUST BE FALSE UNTIL OTP VERIFIED
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            log_action('Customer', new_user.username, 'Signup', 'Auth', 'N/A', 'Success', 'New Account Created')

            # Send Email
            send_otp_email(email, otp)
            print(f"\n[SIGNUP OTP] Code for {email}: {otp}\n")
            
            # Set Session for Verification Step
            session['pending_user_id'] = new_user.id 
            
            return redirect(url_for('store_verify'))
            
        except Exception as e:
            db.session.rollback()
            print(f"Signup Error: {e}") 
            flash(f"System Error: {str(e)}", "danger")
            return render_template('store_signup.html', email=email, form_data=request.form)
            
    return render_template('store_signup.html', email=email, form_data={})

@app.route('/store/verify', methods=['GET', 'POST'])
def store_verify():
    pending_id = session.get('pending_user_id')
    if not pending_id: return redirect(url_for('store_auth'))
        
    user = User.query.get(pending_id)
    if not user: return redirect(url_for('store_auth'))
    
    # Determine if this is a new signup for UI purposes
    is_new_signup = not user.is_verified

    if request.method == 'POST':
        if 'otp' in request.form:
            otp_input = request.form.get('otp')
            
            # Verify OTP
            if user.otp == otp_input and user.otp_expiry > datetime.utcnow():
                user.otp = None
                user.is_verified = True
                db.session.commit()
                
                # --- 1. CHECK FOR ACCOUNT LOCKOUT ---
                if user.failed_attempts >= 5:
                    session['unlock_user_id'] = user.id
                    session.pop('pending_user_id', None)
                    flash("Identity verified. Please change your password to unlock your account.", "warning")
                    return redirect(url_for('store_unlock'))

                # --- 2. CHECK FOR FORGOT PASSWORD FLOW (NEW) ---
                if session.get('reset_flow'):
                    session.pop('reset_flow', None)       # Clear the request flag
                    session['reset_user_id'] = user.id    # Set the permission flag
                    session.pop('pending_user_id', None)  # Clear pending ID
                    return redirect(url_for('store_reset_password'))
                
                # --- 3. STANDARD LOGIN ---
                # [NEW] Log the successful Customer Login
                log_action('Customer', user.username, 'Login', 'Auth', 'N/A', 'Success', 'Logged in via OTP')
                
                session['user_id'] = user.id
                session.pop('auth_email', None)
                session.pop('pending_user_id', None)
                
                flash(f"Welcome back, {user.first_name}!", "success")
                return redirect(url_for('store_home')) 
            else:
                flash("Invalid or expired code.", "danger")
            
    return render_template('store_verify.html', email=user.email, is_new_signup=is_new_signup)

@app.route('/admin/reset_password/<int:user_id>', methods=['POST'])
@admin_required
def reset_password(user_id):
    user = User.query.get_or_404(user_id)
    
    # 1. Capture Form Data
    new_username = request.form.get('new_username')
    new_email = request.form.get('new_email')
    temp_password = request.form.get('temp_password')

    # --- CHECK: Prevent reusing the CURRENT password as the TEMP password ---
    if user.password.startswith('scrypt:') and check_password_hash(user.password, temp_password):
        flash("Error: New password cannot be the same as the user's current password.", "danger")
        return redirect(url_for('admin_panel'))
    
    # --- HISTORY FIX: Archive the OLD password before resetting ---
    # This ensures they can't reuse the password they just "forgot"
    if user.password and user.password.startswith('scrypt:'):
        # Save the old hash to history
        history_entry = PasswordHistory(user_id=user.id, password_hash=user.password)
        db.session.add(history_entry)

    # 2. Update User Record
    if new_username: user.username = new_username
    if new_email: user.email = new_email
    
    # Save the password (plain text for first login)
    user.password = temp_password 
    user.must_change_password = True
    
    db.session.commit()
    
    # 3. Determine Recipient & Send Email
    recipient = new_email if new_email else user.email
    
    status_msg = ""
    if recipient:
        if send_temp_password_email(recipient, temp_password):
            status_msg = f" Notification sent to {recipient}."
        else:
            status_msg = " (Warning: Email failed to send. Check server logs.)"
    else:
        status_msg = " (No email address available to send notification.)"

    # 4. Log & Redirect
    log_action('Admin', g.user.username, 'Reset Password', 'User', user.username, 'Success', 'Admin reset credentials')
    flash(f'Credentials updated for {user.username}.{status_msg}', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/store/resend')
def store_resend():
    pending_id = session.get('pending_user_id')
    if pending_id:
        user = User.query.get(pending_id)
        if user:
            otp = f"{random.randint(100000, 999999)}"
            user.otp = otp
            user.otp_expiry = datetime.utcnow() + timedelta(minutes=10)
            db.session.commit()
            send_otp_email(user.email, otp)
            print(f"\n[RESEND OTP] Code: {otp}\n")
            flash("New code sent!", "success")
    return redirect(url_for('store_verify'))

# --- SOCIAL AUTH ---
@app.route('/auth/google')
def google_login():
    cid = app.config.get('GOOGLE_CLIENT_ID')
    
    # If CID is None or the placeholder text, it means .env isn't loading
    if not cid or "YOUR_REAL" in cid:
        print(f"ERROR: Client ID is missing. Value is: {cid}")
        flash("Google Auth is not configured. Check your .env file.", "danger")
        return redirect(url_for('store_auth'))

    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/google/callback')
def google_callback():
    try:
        if request.args.get('simulated') == 'true':
            email = "demo.google.user@gmail.com"
            first_name = "Google"
            last_name = "User"
        else:
            token = google.authorize_access_token()
            user_info = google.userinfo() # Fixed Nonce Error
            email = user_info['email']
            first_name = user_info.get('given_name', '')
            last_name = user_info.get('family_name', '')

        user = User.query.filter_by(email=email).first()
        
        # 1. Create Account if it doesn't exist
        if not user:
            # --- BUG FIX: Safe ID Generation ---
            # Instead of counting rows (which breaks if you delete users), find the last ID used.
            last_cust = User.query.filter(User.custom_id.like('CUST-%')).order_by(User.id.desc()).first()

            if last_cust and last_cust.custom_id:
                try:
                    # Extract last number (e.g. 'CUST-2026-005' -> 5)
                    last_num = int(last_cust.custom_id.split('-')[-1])
                    new_num = last_num + 1
                except (ValueError, IndexError):
                    new_num = User.query.count() + 1
            else:
                new_num = 1

            custom_id = f"CUST-{datetime.now().year}-{new_num:03d}"
            # -----------------------------------

            user = User(
                custom_id=custom_id, 
                username=email, 
                email=email, 
                password="GOOGLE_OAUTH_USER", 
                first_name=first_name, 
                last_name=last_name, 
                role='Customer', 
                auth_provider='google', 
                profile_image='default.jpg',  # <--- ADDED DEFAULT IMAGE
                is_verified=True
            )
            db.session.add(user)
            db.session.commit()
            
            # New User -> Log in and send to Password Setup
            session['user_id'] = user.id
            flash("Account created! Please set a password to secure your account.", "info")
            return redirect(url_for('store_setup_password'))
        
        # 2. If Account Exists, check Role
        if user.role != 'Customer':
            flash("Staff accounts cannot use Social Login. Please use Admin Login.", "danger")
            return redirect(url_for('login'))

        # --- NEW: SUSPENSION CHECK ---
        if user.is_suspended:
            flash("Your account has been suspended.", "danger")
            return redirect(url_for('store_auth'))
        # -----------------------------

        log_action('Customer', user.username, 'Login', 'Auth', 'N/A', 'Success', f'Logged in via {user.auth_provider.title()}')

        # 3. Log In
        session['user_id'] = user.id
        
        # CHECK: Does this user still have the placeholder password?
        if user.password == "GOOGLE_OAUTH_USER":
            flash("Please set a password for your account.", "info")
            return redirect(url_for('store_setup_password'))

        flash("Successfully signed in with Google.", "success")
        return redirect(url_for('store_home'))

    except Exception as e:
        import traceback
        print("\n\n========== GOOGLE LOGIN ERROR ==========")
        print(f"Error Type: {type(e).__name__}")
        print(f"Error Message: {str(e)}")
        print(traceback.format_exc())
        print("========================================\n\n")
        
        flash(f"Google Sign-In failed: {str(e)}", "danger")
        return redirect(url_for('store_auth'))
    
# Discord Routes
@app.route('/auth/discord')
def discord_login():
    redirect_uri = url_for('discord_callback', _external=True)
    return discord.authorize_redirect(redirect_uri)

@app.route('/auth/discord/callback')
def discord_callback():
    try:
        token = discord.authorize_access_token()
        # Discord returns user info at /users/@me
        resp = discord.get('users/@me')
        user_info = resp.json()
        
        email = user_info.get('email')
        if not email:
            flash("Could not fetch email from Discord.", "danger")
            return redirect(url_for('store_auth'))

        username = user_info.get('username')
        # Discord doesn't really have "First/Last" names, so we approximate
        first_name = username
        last_name = "" 
        
        # --- DATABASE LOGIC (Standard) ---
        user = User.query.filter_by(email=email).first()
        
        if not user:
            # Create Account
            count = User.query.count() + 1
            custom_id = f"CUST-{datetime.now().year}-{count:03d}"
            user = User(
                custom_id=custom_id, 
                username=email, 
                email=email, 
                password="DISCORD_OAUTH_USER", 
                first_name=username, 
                role='Customer', 
                auth_provider='discord', 
                profile_image='default.jpg',  # <--- ADDED DEFAULT IMAGE
                is_verified=True
            )
            db.session.add(user)
            db.session.commit()
            
            session['user_id'] = user.id
            flash("Account created via Discord!", "success")
            return redirect(url_for('store_setup_password'))
        
        if user.role != 'Customer':
            flash("Staff accounts cannot use Social Login.", "danger")
            return redirect(url_for('login'))

      # --- NEW: SUSPENSION CHECK ---
        if user.is_suspended:
            flash("Your account has been suspended.", "danger")
            return redirect(url_for('store_auth'))
        # -----------------------------
        
        log_action('Customer', user.username, 'Login', 'Auth', 'N/A', 'Success', f'Logged in via {user.auth_provider.title()}')

        session['user_id'] = user.id
        flash(f"Welcome back, {first_name}!", "success")
        return redirect(url_for('store_home'))

    except Exception as e:
        flash(f"Discord Login Failed: {str(e)}", "danger")
        return redirect(url_for('store_auth'))

@app.route('/store/setup_password', methods=['GET', 'POST'])
def store_setup_password():
    # Ensure user is logged in (via Google)
    if not g.user:
        flash("Please log in first.", "warning")
        return redirect(url_for('store_auth'))
    
    # Optional: Prevent users with real passwords from accidentally accessing this
    if g.user.password != "GOOGLE_OAUTH_USER":
        return redirect(url_for('store_home'))

    if request.method == 'POST':
        phone = request.form.get('phone')
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')
        
        if password != confirm:
            flash("Passwords do not match.", "danger")
        else:
            valid, msg = is_password_strong(password)
            if not valid:
                flash(f"Weak Password: {msg}", "danger")
            else:
                try:
                    # 1. Update User Details
                    g.user.password = generate_password_hash(password)
                    g.user.phone = phone
                    
                    # 2. Generate OTP for Verification
                    otp = f"{random.randint(100000, 999999)}"
                    g.user.otp = otp
                    g.user.otp_expiry = datetime.utcnow() + timedelta(minutes=10)
                    # We mark them as unverified until they pass this check
                    g.user.is_verified = False 
                    
                    db.session.commit()
                    
                    # 3. Send OTP
                    send_otp_email(g.user.email, otp)
                    print(f"\n[SETUP OTP] Code for {g.user.email}: {otp}\n")
                    
                    # 4. Prepare for Verification Page
                    # We store the ID in 'pending' and LOG THEM OUT so verify works normally
                    session['pending_user_id'] = g.user.id
                    session['auth_email'] = g.user.email
                    session.pop('user_id', None) 
                    
                    flash("Details saved! Please verify your identity to continue.", "success")
                    return redirect(url_for('store_verify'))
                    
                except Exception as e:
                    db.session.rollback()
                    flash(f"Error saving details: {str(e)}", "danger")
                
    return render_template('store_setup_password.html')

@app.route('/store/invoice/pay/<int:invoice_id>')
def store_invoice_pay(invoice_id):
    if not g.user: return redirect(url_for('store_auth'))
    
    # 1. Get Invoice & Verify Ownership
    invoice = Invoice.query.get(invoice_id)
    if not invoice:
        flash("Invoice not found.", "danger")
        return redirect(url_for('store_profile'))
    
    client = Client.query.get(invoice.client_id)
    if not client or client.email != g.user.email:
        flash("Access Denied.", "danger")
        return redirect(url_for('store_home'))
        
    if invoice.status != 'Pending':
        flash(f"This invoice is already {invoice.status}.", "warning")
        return redirect(url_for('store_profile'))

    # 2. Setup Session for Confirmation Page
    session['confirm_order_id'] = invoice.order_id
    
    # Try to reconstruct shipping info from description (Simple extraction)
    # Format was: "PaymentDesc | Ship to: Address"
    desc = invoice.order.description
    address_part = "Address on file"
    if "Ship to:" in desc:
        address_part = desc.split("Ship to:")[1].strip()
        
    session['confirm_shipping'] = {
        'first_name': g.user.first_name,
        'last_name': g.user.last_name,
        'address': address_part,
        'city': '',
        'zip': ''
    }
    
    return redirect(url_for('store_checkout_confirm'))

@app.route('/store/invoice/cancel/<int:invoice_id>')
def store_invoice_cancel(invoice_id):
    if not g.user: return redirect(url_for('store_auth'))
    
    invoice = Invoice.query.get(invoice_id)
    if not invoice: return redirect(url_for('store_profile'))
    
    client = Client.query.get(invoice.client_id)
    if not client or client.email != g.user.email:
        return redirect(url_for('store_home'))
        
    if invoice.status == 'Pending':
        # 1. Update Status
        invoice.status = 'Cancelled'
        if invoice.order:
            invoice.order.status = 'Cancelled'
            
            # 2. RESTOCK ITEMS
            for item in invoice.order.items:
                # Find product by name
                prod = Product.query.filter_by(name=item.item_name).first()
                if prod:
                    prod.stock += item.quantity
                    prod.sales_count -= item.quantity
        
        db.session.commit()
        log_action('Customer', g.user.username, 'Cancel Invoice', 'Invoice', invoice.invoice_code, 'Success', 'User cancelled pending order')
        flash("Invoice cancelled and items returned to stock.", "success")
        
    return redirect(url_for('store_profile'))

@app.route('/store/profile/delete', methods=['POST'])
def delete_account():
    if not g.user: return redirect(url_for('store_auth'))
    
    try:
        # 1. Delete associated payment methods first (Foreign Key cleanup)
        PaymentMethod.query.filter_by(user_id=g.user.id).delete()
        
        # 2. Delete the user record
        username = g.user.username # Save for logging
        db.session.delete(g.user)
        db.session.commit()
        
        # 3. Log user out
        session.clear()
        
        print(f"\n[ACCOUNT DELETED] User: {username}\n")
        flash("Your account has been permanently deleted.", "info")
        return redirect(url_for('store_home'))
        
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting account: {str(e)}", "danger")
        return redirect(url_for('store_profile'))

@app.route('/store/logout')
def store_logout():
    if g.user:
        log_action('Customer', g.user.username, 'Logout', 'Auth', 'N/A', 'Success', 'Customer Logged Out')
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for('store_auth'))

# --- PROFILE & SETTINGS ROUTES ---

@app.route('/store/profile')
def store_profile():
    if not g.user: return redirect(url_for('store_auth'))
    
    # 1. Check for incomplete signup
    incomplete = check_incomplete_signup()
    if incomplete: return incomplete
    
    # 2. RUN EXPIRY CHECK
    check_invoice_expiry()

    # --- FIX: CLEAR STALE OTP FLAGS ---
    # If the user has a "Show Modal" flag but the OTP is expired or missing, clear it.
    if session.get('show_password_verify'):
        # If no OTP exists or it has expired
        if not g.user.otp or (g.user.otp_expiry and g.user.otp_expiry < datetime.utcnow()):
            session.pop('show_password_verify', None)
            g.user.otp = None
            db.session.commit()
            print("[SYSTEM] Cleared stale OTP session flag")
    # ----------------------------------
    
    # 3. Load Data
    client = Client.query.filter_by(email=g.user.email).first()
    orders = []
    invoices = []
    if client:
        orders = Order.query.filter_by(client_id=client.id).order_by(Order.date_placed.desc()).all()
        invoices = Invoice.query.filter_by(client_id=client.id).order_by(Invoice.date_created.desc()).all()
        
    payment_methods = g.user.payment_methods
    return render_template('store_profile.html', user=g.user, orders=orders, invoices=invoices, payment_methods=payment_methods)

@app.route('/store/profile/update', methods=['POST'])
def update_profile():
    if not g.user: return redirect(url_for('store_auth'))
    g.user.first_name = request.form.get('first_name')
    g.user.last_name = request.form.get('last_name')
    g.user.phone = request.form.get('phone')
    if 'profile_image' in request.files:
        file = request.files['profile_image']
        if file and file.filename != '' and allowed_file(file.filename):
            filename = secure_filename(f"user_{g.user.id}_{file.filename}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            g.user.profile_image = filename
    db.session.commit()
    log_action('Customer', g.user.username, 'Update Profile', 'User', g.user.id, 'Success', 'Updated Personal Details')
    flash("Profile updated successfully.", "success")
    return redirect(url_for('store_profile'))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- NEW: Profile Picture Upload Route ---
@app.route('/store/profile/upload_pic', methods=['POST'])
def upload_profile_pic():
    # 1. Security Check
    if not g.user:
        return redirect(url_for('store_auth'))
        
    # 2. Check if file is present
    if 'profile_pic' not in request.files:
        flash('No file selected.', 'danger')
        return redirect(url_for('store_profile'))
    
    file = request.files['profile_pic']
    
    # 3. Check if filename is empty
    if file.filename == '':
        flash('No file selected.', 'danger')
        return redirect(url_for('store_profile'))
        
    # 4. Validate and Save
    if file and allowed_file(file.filename):
        try:
            # Create a safe, unique filename (e.g., user_5_20231024.jpg) to prevent overwrites
            file_ext = file.filename.rsplit('.', 1)[1].lower()
            new_filename = f"user_{g.user.id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.{file_ext}"
            
            # Save the file
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], new_filename))
            
            # Update Database
            g.user.profile_image = new_filename
            db.session.commit()
            log_action('Customer', g.user.username, 'Update Picture', 'User', g.user.id, 'Success', 'Changed Profile Picture')
            flash('Profile picture updated successfully!', 'success')
            
        except Exception as e:
            flash(f'Error saving image: {str(e)}', 'danger')
            
    else:
        flash('Invalid file type. Allowed: PNG, JPG, JPEG', 'warning')
        
    return redirect(url_for('store_profile'))

@app.route('/store/profile/security', methods=['POST'])
def security_update():
    if not g.user: return redirect(url_for('store_auth'))
    current_pw = request.form.get('current_password')
    new_pw = request.form.get('new_password')
    
    # 1. Validate Current Password
    is_correct = False
    if g.user.password.startswith('scrypt:'):
         is_correct = check_password_hash(g.user.password, current_pw)
    else:
         is_correct = (g.user.password == current_pw)

    if current_pw and new_pw:
        if is_correct:
            if current_pw == new_pw:
                flash("New password cannot be the same as your current password.", "danger")
                return redirect(url_for('store_profile'))
            
            # 2. Validate New Password Strength
            valid, msg = is_password_strong(new_pw)
            if not valid:
                flash(f"Security Error: {msg}", "danger")
            else:
                # 3. Generate OTP & Save
                otp = f"{random.randint(100000, 999999)}"
                g.user.new_password_temp = generate_password_hash(new_pw)
                g.user.otp = otp
                g.user.otp_expiry = datetime.utcnow() + timedelta(minutes=10)
                db.session.commit()
                
                # 4. SEND EMAIL
                email_sent = send_otp_email(g.user.email, otp)
                
                if email_sent:
                    flash(f"Verification code sent to {g.user.email}", "info")
                else:
                    # FALLBACK if SMTP fails
                    flash(f"Dev Mode: Verification code is {otp}", "warning")
                
                session['show_password_verify'] = True
        else:
            flash("Incorrect current password.", "danger")
    return redirect(url_for('store_profile'))

@app.route('/store/profile/verify_security', methods=['POST'])
def verify_security():
    if not g.user: return redirect(url_for('store_auth'))
    otp_input = request.form.get('otp')
    if g.user.otp == otp_input and g.user.otp_expiry > datetime.utcnow():
        g.user.password = g.user.new_password_temp
        g.user.new_password_temp = None
        g.user.otp = None
        db.session.commit()
        log_action('Customer', g.user.username, 'Security Update', 'User', g.user.id, 'Success', 'Changed Password')
        session.pop('show_password_verify', None)
        flash("Password successfully changed.", "success")
    else:
        flash("Invalid or expired OTP.", "danger")
        session['show_password_verify'] = True
    return redirect(url_for('store_profile'))

@app.route('/store/profile/cancel_verify')
def cancel_verify():
    """Cancels the verification process and clears session flags."""
    session.pop('show_password_verify', None)
    # session.pop('show_email_verify', None) <--- Removed as email OTP is gone
    
    if g.user:
        g.user.otp = None
        g.user.new_password_temp = None
        # g.user.new_email_temp = None <--- Removed
        db.session.commit()
        
    flash("Verification cancelled.", "info")
    return redirect(url_for('store_profile'))

@app.route('/store/profile/email_otp', methods=['POST'])
def request_email_change():
    if not g.user: return redirect(url_for('store_auth'))
    new_email = request.form.get('new_email')
    if new_email:
        if User.query.filter_by(email=new_email).first():
            flash("This email is already in use.", "danger")
        else:
            otp = f"{random.randint(100000, 999999)}"
            g.user.new_email_temp = new_email
            g.user.otp = otp
            g.user.otp_expiry = datetime.utcnow() + timedelta(minutes=10)
            db.session.commit()
            
            send_otp_email(g.user.email, otp)
            
            flash(f"OTP sent to your current email.", "info")
            session['show_email_verify'] = True
    return redirect(url_for('store_profile'))

@app.route('/store/profile/verify_email', methods=['POST'])
def verify_email_change():
    if not g.user: return redirect(url_for('store_auth'))
    otp_input = request.form.get('otp')
    if g.user.otp == otp_input and g.user.otp_expiry > datetime.utcnow():
        g.user.email = g.user.new_email_temp
        g.user.username = g.user.new_email_temp 
        g.user.new_email_temp = None
        g.user.otp = None
        db.session.commit()
        log_action('Customer', g.user.username, 'Security Update', 'User', g.user.id, 'Success', 'Changed Email Address')
        session.pop('show_email_verify', None)
        flash("Email address updated successfully.", "success")
    else:
        flash("Invalid OTP.", "danger")
        session['show_email_verify'] = True
    return redirect(url_for('store_profile'))

@app.route('/store/profile/update_email', methods=['POST'])
def update_email_address():
    if not g.user: return redirect(url_for('store_auth'))
    
    new_email = request.form.get('new_email')
    current_password = request.form.get('current_password')
    
    if not new_email or not current_password:
        flash("Please provide both the new email and your current password.", "warning")
        return redirect(url_for('store_profile'))

    # 1. Verify Current Password
    is_correct = False
    if g.user.password.startswith('scrypt:'):
         is_correct = check_password_hash(g.user.password, current_password)
    else:
         is_correct = (g.user.password == current_password)
         
    if not is_correct:
        flash("Incorrect password. Email update failed.", "danger")
        return redirect(url_for('store_profile'))

    # 2. Check Uniqueness
    if User.query.filter_by(email=new_email).first():
        flash("This email address is already in use.", "danger")
        return redirect(url_for('store_profile'))

    # 3. Update Email
    old_email = g.user.email
    g.user.email = new_email
    # Optionally update username if it mirrors email, though typically username is unique/static
    if g.user.username == old_email:
        g.user.username = new_email
        
    db.session.commit()
    
    log_action('Customer', g.user.username, 'Update Profile', 'User', g.user.id, 'Success', f'Changed Email from {old_email} to {new_email}')
    flash("Email address updated successfully.", "success")
    return redirect(url_for('store_profile'))

@app.route('/store/profile/payment', methods=['POST'])
def update_payment():
    if not g.user: 
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
             return jsonify({'status': 'error', 'message': 'Login required'}), 401
        return redirect(url_for('store_auth'))
    
    cardholder = request.form.get('cardholder_name')
    card_number = request.form.get('card_number', '').replace(' ', '')
    expiry = request.form.get('expiry')
    
    if card_number and expiry and cardholder:
        last4 = card_number[-4:]
        
        # Simple Brand Detection
        card_type = "Visa"
        if card_number.startswith('5'): card_type = "Mastercard"
        elif card_number.startswith('34') or card_number.startswith('37'): card_type = "Amex"
        elif card_number.startswith('6'): card_type = "Discover"
        
        new_card = PaymentMethod(
            user_id=g.user.id, 
            cardholder_name=cardholder,
            card_type=card_type, 
            last4=last4, 
            expiry=expiry
        )
        db.session.add(new_card)
        db.session.commit()
        log_action('Customer', g.user.username, 'Update Payment', 'PaymentMethod', new_card.last4, 'Success', f'Added {new_card.card_type}')
        
        # --- NEW: AJAX Response ---
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'status': 'success',
                'message': 'Card added successfully',
                'card': {
                    'id': new_card.id,
                    'card_type': new_card.card_type,
                    'last4': new_card.last4,
                    'expiry': new_card.expiry,
                    'cardholder_name': new_card.cardholder_name
                }
            })

        flash(f"{card_type} ending in {last4} added.", "success")
    else:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
             return jsonify({'status': 'error', 'message': 'Invalid card details'}), 400
        flash("Invalid card details.", "danger")
    return redirect(url_for('store_profile'))

@app.route('/store/profile/delete_payment/<int:pm_id>', methods=['GET', 'POST', 'DELETE'])
def delete_payment(pm_id):
    if not g.user: return redirect(url_for('store_auth'))
    pm = PaymentMethod.query.get(pm_id)
    
    if pm and pm.user_id == g.user.id:
        db.session.delete(pm)
        db.session.commit()
        
        # --- NEW: AJAX Response ---
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
             return jsonify({'status': 'success', 'message': 'Card removed'})
             
        flash("Payment method removed.", "success")
        
    return redirect(url_for('store_profile'))

# --- CART & CHECKOUT ---

@app.route('/cart', methods=['GET', 'POST'])
def store_cart():
    if 'cart' not in session: session['cart'] = {}
    
    if request.method == 'POST':
        p_id = request.form.get('product_id')
        qty = int(request.form.get('quantity', 1))
        size = request.form.get('size', 'One Size')
        color = request.form.get('color', 'Default')
        
        # Sanitize inputs
        if not size or size == 'None': size = 'One Size'
        if not color or color == 'None': color = 'Default'

        product = Product.query.get(p_id)
        if product:
            cart = session['cart']
            # Create Unique Key: ProductID-Size-Color
            cart_key = f"{p_id}-{size.replace(' ','')}-{color.replace(' ','')}"
            
            if cart_key in cart: 
                cart[cart_key]['qty'] += qty
            else:
                cart[cart_key] = {
                    'product_id': p_id,
                    'name': product.name, 
                    'price': product.price, 
                    'qty': qty, 
                    'image': product.image_url.split('|')[0], 
                    'category': product.category,
                    'size': size,
                    'color': color
                }
            session.modified = True
            
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return json.dumps({'status': 'success', 'cart_count': sum(i['qty'] for i in cart.values())})
            
            return redirect(request.referrer or url_for('store_cart'))
        
    totals = calculate_cart_totals(session['cart'])
    
    # Prepare items for display (fetching variant options for the dropdowns)
    cart_items = []
    for key, item in session['cart'].items():
        item['key'] = key
        item['total'] = item['price'] * item['qty']
        prod = Product.query.get(item['product_id'])
        if prod:
            item['all_sizes'] = prod.sizes.split(',') if prod.sizes else []
            item['all_colors'] = prod.colors.split(',') if prod.colors else []
        cart_items.append(item)
        
    return render_template('store_cart.html', cart_items=cart_items, totals=totals)

@app.route('/cart/update', methods=['POST'])
def update_cart():
    if 'cart' not in session: return redirect(url_for('store_cart'))
    
    # FIX: Look for 'cart_key' instead of 'product_id'
    cart_key = request.form.get('cart_key')
    action = request.form.get('action')
    
    if cart_key and cart_key in session['cart']:
        if action == 'increase': 
            session['cart'][cart_key]['qty'] += 1
        elif action == 'decrease': 
            session['cart'][cart_key]['qty'] -= 1
        elif action == 'delete': 
            del session['cart'][cart_key]
        
        # Auto-remove if quantity hits 0
        if cart_key in session['cart'] and session['cart'][cart_key]['qty'] <= 0: 
            del session['cart'][cart_key]
            
    session.modified = True
    return redirect(url_for('store_cart'))

@app.route('/cart/edit_variant', methods=['POST'])
def edit_cart_variant():
    if 'cart' not in session: return redirect(url_for('store_cart'))
    
    old_key = request.form.get('cart_key')
    new_size = request.form.get('new_size')
    new_color = request.form.get('new_color')
    
    if old_key in session['cart']:
        item = session['cart'][old_key]
        p_id = item['product_id']
        
        # Generate new key and merge if exists
        new_key = f"{p_id}-{new_size.replace(' ','')}-{new_color.replace(' ','')}"
        
        if new_key != old_key:
            if new_key in session['cart']:
                session['cart'][new_key]['qty'] += item['qty']
            else:
                new_item = item.copy()
                new_item['size'] = new_size
                new_item['color'] = new_color
                session['cart'][new_key] = new_item
            
            del session['cart'][old_key]
            session.modified = True
            
    return redirect(url_for('store_cart'))

# ==============================================================================
# CHECKOUT FLOW: CREATE PENDING -> CONFIRM -> PAID
# ==============================================================================

@app.route('/checkout', methods=['GET', 'POST'])
def store_checkout():
    if not g.user:
        flash("Please sign in to checkout.", "warning")
        return redirect(url_for('store_auth')) 
        
    if not g.user.is_verified:
        session['pending_user_id'] = g.user.id
        session['auth_email'] = g.user.email
        flash("Please verify your email address to continue.", "warning")
        return redirect(url_for('store_verify'))
        
    if not session.get('cart'): return redirect(url_for('store_shop'))
    
    totals = calculate_cart_totals(session['cart'])
    
    if request.method == 'POST':
        try:
            # 1. Capture Payment Selection
            payment_type = request.form.get('payment_type')
            payment_desc = "Unknown"
            
            if payment_type == 'card':
                card_choice = request.form.get('card_choice')
                if card_choice == 'saved':
                    pm_id = request.form.get('saved_pm_id')
                    pm = PaymentMethod.query.get(pm_id)
                    if pm and pm.user_id == g.user.id:
                        payment_desc = f"Saved {pm.card_type} (**{pm.last4})"
                    else: raise Exception("Invalid saved card.")
                elif card_choice == 'new':
                    c_num = request.form.get('card_number', '').replace(' ', '')
                    if len(c_num) < 13: raise Exception("Invalid Card Number")
                    brand = "Visa"
                    if c_num.startswith('5'): brand = "Mastercard"
                    payment_desc = f"New {brand} (**{c_num[-4:]})"
            else:
                payment_desc = f"{payment_type.title()}"

# 2. Capture Shipping & Remarks
            remarks = request.form.get('remarks', '').strip()
            shipping_info = {
                'first_name': request.form.get('first_name'),
                'last_name': request.form.get('last_name'),
                'address': request.form.get('address'),
                'city': request.form.get('city'),
                'zip': request.form.get('zip'),
                'remarks': remarks
            }

            # 3. CREATE RECORDS
            client = Client.query.filter_by(email=g.user.email).first()
            if not client:
                client = Client(name=f"{g.user.first_name} {g.user.last_name}", email=g.user.email, company="Online Customer")
                db.session.add(client)
                db.session.commit()

            order_code = f"ORD-{datetime.now().strftime('%Y%m%d')}-{random.randint(1000,9999)}"
            
            # Combine the payment description, address, and remarks
            full_desc = f"{payment_desc} | Ship to: {shipping_info['address']}"
            if remarks:
                full_desc += f" | Remarks: {remarks}"
            
            new_order = Order(
                order_code=order_code, 
                client_id=client.id,
                description=full_desc[:200], # Ensures it doesn't exceed DB limits
                amount=totals['grand_total'], 
                status='Pending',
                date_placed=datetime.utcnow()
            )
            db.session.add(new_order)
            db.session.flush()

            # --- FIXED: Handle Composite Keys (e.g. "4-OneSize-Default") ---
            for cart_key, item in session['cart'].items():
                
                # 1. Format Item Name with Variants (e.g., "T-Shirt (Red, L)")
                display_name = item['name']
                if 'size' in item and 'color' in item:
                    display_name += f" ({item['color']}, {item['size']})"
                elif 'size' in item:
                    display_name += f" ({item['size']})"
                
                # 2. Create Order Item
                order_item = OrderItem(
                    order_id=new_order.id, 
                    item_name=display_name, 
                    quantity=item['qty'], 
                    unit_price=item['price'], 
                    total_price=item['price'] * item['qty']
                )
                db.session.add(order_item)
                
                # 3. Extract Real Product ID for Stock Deduction
                try:
                    # If key is "4-Red-L", split gives ['4', 'Red', 'L'], index 0 is '4'
                    real_p_id = int(str(cart_key).split('-')[0])
                    prod = Product.query.get(real_p_id)
                    if prod:
                        prod.stock -= item['qty']
                        prod.sales_count += item['qty']
                except (ValueError, IndexError):
                    print(f"Error deducting stock for key: {cart_key}")

            # Add Fees
            if totals['shipping'] > 0: 
                db.session.add(OrderItem(order_id=new_order.id, item_name="Shipping Fee", quantity=1, unit_price=totals['shipping'], total_price=totals['shipping']))
            if totals['gst'] > 0: 
                db.session.add(OrderItem(order_id=new_order.id, item_name="GST (9%)", quantity=1, unit_price=totals['gst'], total_price=totals['gst']))

            # Create Invoice
            inv_code = f"INV-{datetime.now().strftime('%Y%m%d')}-{random.randint(100,999)}"
            new_invoice = Invoice(
                invoice_code=inv_code, 
                order_id=new_order.id, 
                client_id=client.id, 
                amount=totals['grand_total'], 
                status='Pending',
                date_created=datetime.utcnow(), 
                date_due=datetime.utcnow() + timedelta(days=7)
            )
            db.session.add(new_invoice)
            db.session.commit()
            
            session['confirm_order_id'] = new_order.id
            session['confirm_shipping'] = shipping_info
            
            return redirect(url_for('store_checkout_confirm'))
            
        except Exception as e:
            db.session.rollback()
            flash(f"Error: {str(e)}", "danger")
            return redirect(url_for('store_checkout'))

    return render_template('store_checkout.html', totals=totals, user=g.user, saved_methods=g.user.payment_methods)

@app.route('/checkout/confirm')
def store_checkout_confirm():
    if not g.user: return redirect(url_for('store_auth'))
    
    # Fetch the Pending Order from DB
    order_id = session.get('confirm_order_id')
    if not order_id: return redirect(url_for('store_checkout'))
    
    order = Order.query.get(order_id)
    if not order: return redirect(url_for('store_checkout'))
    
    # Security: Ensure this order belongs to current user
    client = Client.query.get(order.client_id)
    if client.email != g.user.email: return redirect(url_for('store_home'))

    # Load shipping info from session (since DB doesn't have it)
    shipping_info = session.get('confirm_shipping', {})
    
    return render_template('store_checkout_confirm.html', order=order, shipping_info=shipping_info)

@app.route('/checkout/process', methods=['POST'])
def store_checkout_process():
    if not g.user: return redirect(url_for('store_auth'))
    
    order_id = session.get('confirm_order_id')
    if not order_id: return redirect(url_for('store_checkout'))
    
    try:
        order = Order.query.get(order_id)
        if order and order.status == 'Pending':
            # MARK AS PAID
            order.status = 'Invoiced'
            if order.invoice:
                order.invoice.status = 'Paid'
            
            db.session.commit()
            
            # Log
            log_action('Customer', g.user.username, 'Online Purchase', 'Order', order.order_code, 'Success', "Payment Completed")
            
            # Cleanup Session
            session.pop('cart', None)
            session.pop('confirm_order_id', None)
            session.pop('confirm_shipping', None)
            
            return redirect(url_for('store_checkout_success', order_code=order.order_code))
        else:
            # Already paid or invalid
            return redirect(url_for('store_home'))
            
    except Exception as e:
        db.session.rollback()
        flash(f"Processing Error: {str(e)}", "danger")
        return redirect(url_for('store_home'))

@app.route('/checkout/cancel')
def store_checkout_cancel():
    # User clicked Cancel at confirmation
    # The record REMAINS in DB as 'Pending'
    session.pop('confirm_order_id', None)
    session.pop('confirm_shipping', None)
    session.pop('cart', None) # Clear cart since the order is technically created (just pending payment)
    
    flash("Order saved. You can complete payment or cancel this order in your Profile Invoice History.", "info")
    return redirect(url_for('store_home'))

@app.route('/checkout/success/<order_code>')
def store_checkout_success(order_code):
    if not g.user: return redirect(url_for('store_auth'))
    
    order = Order.query.filter_by(order_code=order_code).first()
    
    # --- LOGIC TO MATCH ORDER ITEMS BACK TO PRODUCTS FOR REVIEW ---
    reviewable_items = []
    if order:
        for item in order.items:
            # Skip non-product items (Fees/Tax)
            if "Shipping Fee" in item.item_name or "GST" in item.item_name:
                continue

            # FIX: Use rsplit (Right Split) to only remove the LAST parenthesis group (the variant info)
            # This preserves product names that naturally have brackets like "Vintage Tee (Unisex) (Red, L)"
            base_name = item.item_name.rsplit(' (', 1)[0]
            
            product = Product.query.filter_by(name=base_name).first()
            
            if product:
                reviewable_items.append({
                    'product_id': product.id,
                    'name': item.item_name
                })
            else:
                # Fallback: Try exact match if rsplit failed or name has no variants
                product = Product.query.filter_by(name=item.item_name).first()
                if product:
                    reviewable_items.append({'product_id': product.id, 'name': item.item_name})
    
    return render_template('store_checkout_success.html', order_code=order_code, order=order, reviewable_items=reviewable_items)
@app.route('/review/submit_checkout', methods=['POST'])
def submit_checkout_review():
    if not g.user:
        flash("Please log in to review.", "warning")
        return redirect(url_for('store_auth'))
        
    try:
        # 1. Capture Data
        product_id = request.form.get('product_id')
        rating = request.form.get('rating')
        title = request.form.get('title')
        comment = request.form.get('comment')
        order_code = request.form.get('order_code')
        
        if not product_id or not rating:
            flash("Please select an item and a rating.", "danger")
            return redirect(url_for('store_checkout_success', order_code=order_code))

        # 2. Create Review
        new_review = Review(
            product_id=int(product_id),
            user_id=g.user.id,
            rating=int(rating),
            title=title if title else f"Review by {g.user.first_name}",
            comment=comment,
            date_posted=datetime.utcnow()
        )
        
        db.session.add(new_review)
        db.session.commit()
        
        # 3. Log Action
        log_action('Customer', g.user.username, 'Created Review', 'Product', product_id, 'Success', 'Review from Checkout')
        
        # 4. REDIRECT BACK TO LOOP (Enable reviewing the next item)
        flash("Review submitted! You can review another item or click Done.", "success")
        return redirect(url_for('store_checkout_success', order_code=order_code))
        
    except Exception as e:
        db.session.rollback()
        flash(f"Error submitting review: {str(e)}", "danger")
        return redirect(url_for('store_home'))

@app.route('/review/<order_code>', methods=['GET', 'POST'])
def store_review(order_code):
    if not g.user: return redirect(url_for('store_auth'))
    
    order = Order.query.filter_by(order_code=order_code).first()
    if not order:
        flash("Order not found.", "danger")
        return redirect(url_for('store_home'))
        
    # Verify User Owns This Order
    client = Client.query.get(order.client_id)
    if not client or client.email != g.user.email:
        flash("Access Denied.", "danger")
        return redirect(url_for('store_home'))
        
    if request.method == 'POST':
        rating = int(request.form.get('rating'))
        comment = request.form.get('comment')
        
        # Update or Create Review
        existing = Review.query.filter_by(order_id=order.id).first()
        if existing:
            existing.rating = rating
            existing.comment = comment
            flash("Review updated!", "success")
        else:
            review = Review(order_id=order.id, user_id=g.user.id, rating=rating, comment=comment)
            db.session.add(review)
            flash("Thank you for your review!", "success")
        
        db.session.commit()
        return redirect(url_for('store_home'))
        
    return render_template('store_review.html', order=order)

# [IN app.py - REPLACE THE store_product FUNCTION]
@app.route('/product/<int:product_id>')
def store_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    # 1. Recommendations (Unchanged)
    recommendations = Product.query.filter(
        Product.category == product.category, 
        Product.id != product_id
    ).limit(4).all()
    
    # 2. Filter & Sort Reviews
    rating_filter = request.args.get('rating')
    sort_filter = request.args.get('sort', 'newest') # Default to newest
    
    query = Review.query.filter_by(product_id=product_id)
    
    # Apply Rating Filter
    if rating_filter and rating_filter.isdigit():
        query = query.filter(Review.rating == int(rating_filter))
        
    # Apply Sorting
    if sort_filter == 'oldest':
        query = query.order_by(Review.date_posted.asc())
    elif sort_filter == 'highest':
        query = query.order_by(Review.rating.desc())
    elif sort_filter == 'lowest':
        query = query.order_by(Review.rating.asc())
    else: # newest
        query = query.order_by(Review.date_posted.desc())
        
    reviews = query.all()
    
    # Calculate counts for the filter dropdowns (Optional polish)
    reviews_count = len(reviews)
    
    return render_template('store_product.html', 
                           product=product, 
                           recommendations=recommendations, 
                           reviews=reviews,
                           current_rating=rating_filter,
                           current_sort=sort_filter)

@app.route('/product/add_review/<int:product_id>', methods=['POST'])
def add_product_review(product_id):
    if not g.user:
        flash("Please log in to write a review.", "warning")
        return redirect(url_for('store_auth'))
        
    try:
        rating = int(request.form.get('rating'))
        title = request.form.get('title')
        comment = request.form.get('comment')
        
        new_review = Review(
            product_id=product_id,
            user_id=g.user.id,
            rating=rating,
            title=title,
            comment=comment
        )
        db.session.add(new_review)
        db.session.commit()
        flash("Review submitted successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error submitting review: {str(e)}", "danger")
        
    return redirect(url_for('store_product', product_id=product_id))

# ==============================================================================
# SECTION 7: ADMIN PANEL ROUTES (PRESERVED & FIXED LOGGING)
# ==============================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user:
            # 1. Check if suspended
            if user.is_suspended:
                flash("This account has been suspended. Please contact a SuperAdmin to unlock it.", "danger")
                return render_template('login.html')

            # 2. Check Password (Supports both Plain Text Temp Passwords & Hashed)
            is_valid = False
            if user.password.startswith('scrypt:'):
                is_valid = check_password_hash(user.password, password)
            else:
                is_valid = (user.password == password)

            if is_valid:
                # SEPARATION CHECK: Ensure Customers cannot use Admin Panel
                if user.role == 'Customer':
                    flash("Access Denied: Customers must use the Store Login.", "danger")
                    return redirect(url_for('store_auth'))
                
                # --- NEW: FIRST LOGIN / TEMP PASSWORD CHECK ---
                if user.must_change_password:
                    session['user_id'] = user.id
                    flash("Welcome! For security, please set your email and a new password.", "info")
                    return redirect(url_for('change_password'))
                # ----------------------------------------------

                # SUCCESS
                user.failed_attempts = 0
                db.session.commit()
                
                session['user_id'] = user.id
                log_action('Admin', user.username, 'Login', 'Auth', 'N/A', 'Success', 'Admin Panel Login')
                return redirect(url_for('dashboard'))
            
            else:
                # FAILURE: Increment counter
                user.failed_attempts = (user.failed_attempts or 0) + 1
                db.session.commit()
                
                remaining = 5 - user.failed_attempts
                if remaining <= 0:
                    user.is_suspended = True
                    db.session.commit()
                    log_action('System', 'Security', 'Suspend User', 'User', user.username, 'Warning', 'Locked out due to failed logins')
                    flash("Account suspended due to too many failed login attempts.", "danger")
                else:
                    flash(f"Invalid Admin Credentials. {remaining} attempts remaining.", "danger")
        else:
            flash("Invalid Admin Credentials", "danger")
            
    return render_template('login.html')

# ==============================================================================
# ADMIN PRODUCT MANAGEMENT
# ==============================================================================
@app.route('/admin/products')
@admin_required
def admin_products():
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('q', '').strip()
    
    query = Product.query
    if search_query:
        query = query.filter(or_(
            Product.name.ilike(f'%{search_query}%'),
            Product.category.ilike(f'%{search_query}%')
        ))
        
    products_pagination = query.order_by(Product.id.desc()).paginate(page=page, per_page=15, error_out=False)
    return render_template('admin_products.html', products=products_pagination)

@app.route('/admin/product/new', methods=['GET', 'POST'])
@admin_required
def admin_product_new():
    if request.method == 'POST':
        try:
            # 1. Handle Images
            images = request.files.getlist('images')
            image_filenames = []
            
            for img in images:
                if img and img.filename != '' and allowed_file(img.filename):
                    file_ext = img.filename.rsplit('.', 1)[1].lower()
                    # Generate safe, unique filename
                    filename = secure_filename(f"prod_{datetime.now().strftime('%Y%m%d%H%M%S')}_{random.randint(1000,9999)}.{file_ext}")
                    img.save(os.path.join(app.config['PRODUCT_UPLOAD_FOLDER'], filename))
                    image_filenames.append(filename)
            
            image_url_string = "|".join(image_filenames) if image_filenames else "default_product.jpg"

            # 2. Create Product
            new_prod = Product(
                name=request.form.get('name'),
                price=float(request.form.get('price', 0)),
                category=request.form.get('category'),
                description=request.form.get('description'),
                stock=int(request.form.get('stock', 0)),
                sizes=request.form.get('sizes'),
                colors=request.form.get('colors'),
                image_url=image_url_string
            )
            
            db.session.add(new_prod)
            db.session.commit()
            
            log_action('Admin', g.user.username, 'Create Product', 'Product', new_prod.name, 'Success', 'Added new product')
            flash("Product created successfully.", "success")
            return redirect(url_for('admin_products'))
            
        except Exception as e:
            db.session.rollback()
            flash(f"Error creating product: {str(e)}", "danger")
            
    return render_template('admin_product_form.html', product=None)

@app.route('/admin/product/edit/<int:prod_id>', methods=['GET', 'POST'])
@admin_required
def admin_product_edit(prod_id):
    product = Product.query.get_or_404(prod_id)
    
    if request.method == 'POST':
        try:
            product.name = request.form.get('name')
            product.price = float(request.form.get('price', 0))
            product.category = request.form.get('category')
            product.description = request.form.get('description')
            product.stock = int(request.form.get('stock', 0))
            product.sizes = request.form.get('sizes')
            product.colors = request.form.get('colors')
            
            # Handle Image Replacement (Only updates if new files are uploaded)
            images = request.files.getlist('images')
            if images and images[0].filename != '':
                image_filenames = []
                for img in images:
                    if img and allowed_file(img.filename):
                        file_ext = img.filename.rsplit('.', 1)[1].lower()
                        filename = secure_filename(f"prod_{datetime.now().strftime('%Y%m%d%H%M%S')}_{random.randint(1000,9999)}.{file_ext}")
                        img.save(os.path.join(app.config['PRODUCT_UPLOAD_FOLDER'], filename))
                        image_filenames.append(filename)
                
                if image_filenames:
                    product.image_url = "|".join(image_filenames)

            db.session.commit()
            log_action('Admin', g.user.username, 'Update Product', 'Product', product.name, 'Success', 'Updated product details')
            flash("Product updated successfully.", "success")
            return redirect(url_for('admin_products'))
            
        except Exception as e:
            db.session.rollback()
            flash(f"Error updating product: {str(e)}", "danger")

    return render_template('admin_product_form.html', product=product)

@app.route('/admin/product/delete/<int:prod_id>', methods=['POST'])
@admin_required
def admin_product_delete(prod_id):
    try:
        product = Product.query.get_or_404(prod_id)
        prod_name = product.name
        db.session.delete(product)
        db.session.commit()
        log_action('Admin', g.user.username, 'Delete Product', 'Product', prod_name, 'Success', 'Deleted product')
        flash("Product deleted successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash("Error: Cannot delete product. It may be linked to existing orders.", "danger")
        
    return redirect(url_for('admin_products'))
# ==============================================================================
# UPDATED DASHBOARD ROUTE (With CSAT & Cancellation Metrics)
# ==============================================================================
# ==============================================================================
# NEW API: DYNAMIC REVENUE DATA (Daily, Weekly, Monthly, Yearly)
# ==============================================================================
@app.route('/api/revenue-trends')
def revenue_trends():
    if not g.user or g.user.role == 'Customer': 
        return jsonify({'error': 'Unauthorized'}), 401

    period = request.args.get('period', 'monthly') # daily, weekly, monthly, yearly
    
    # SQLite Date Formatting
    if period == 'daily':
        date_fmt = '%Y-%m-%d'
    elif period == 'weekly':
        date_fmt = '%Y-%W'
    elif period == 'yearly':
        date_fmt = '%Y'
    else: # monthly (default)
        date_fmt = '%Y-%m'

    # Query: Sum Amount Grouped by Date Format
    data = db.session.query(
        func.strftime(date_fmt, Invoice.date_created).label('date_group'),
        func.sum(Invoice.amount).label('total')
    ).filter(
        Invoice.status == 'Paid'
    ).group_by(
        'date_group'
    ).order_by(
        'date_group'
    ).all()

    # Format for Chart.js
    labels = [row.date_group for row in data]
    values = [row.total for row in data]

    return jsonify({'labels': labels, 'values': values})
@app.route('/dashboard')
def dashboard():
    if not g.user or g.user.role == 'Customer': 
        return redirect(url_for('login'))

    # --- DATE SETUP ---
    now = datetime.now()
    curr_month = now.month
    curr_year = now.year
    last_month_date = now.replace(day=1) - timedelta(days=1)
    last_month = last_month_date.month
    last_year = last_month_date.year

    # --- KPI 1: TOTAL REVENUE ---
    total_revenue = db.session.query(func.sum(Invoice.amount)).filter(Invoice.status == 'Paid').scalar() or 0
    
    # Revenue Growth
    rev_this_month = db.session.query(func.sum(Invoice.amount)).filter(
        Invoice.status == 'Paid', extract('month', Invoice.date_created) == curr_month, extract('year', Invoice.date_created) == curr_year
    ).scalar() or 0
    rev_last_month = db.session.query(func.sum(Invoice.amount)).filter(
        Invoice.status == 'Paid', extract('month', Invoice.date_created) == last_month, extract('year', Invoice.date_created) == last_year
    ).scalar() or 0
    
    revenue_growth = 0
    if rev_last_month > 0:
        revenue_growth = ((rev_this_month - rev_last_month) / rev_last_month) * 100

    # --- KPI 2: TOTAL ORDERS ---
    total_orders = Order.query.count()
    
    # Orders Growth
    orders_this_month = Order.query.filter(extract('month', Order.date_placed) == curr_month, extract('year', Order.date_placed) == curr_year).count()
    orders_last_month = Order.query.filter(extract('month', Order.date_placed) == last_month, extract('year', Order.date_placed) == last_year).count()
    
    order_growth = 0
    if orders_last_month > 0:
        order_growth = ((orders_this_month - orders_last_month) / orders_last_month) * 100

    # --- KPI 3: ACTIVE CUSTOMERS ---
    total_customers = User.query.filter_by(role='Customer', is_suspended=False).count()

    # --- KPI 4: AVERAGE ORDER VALUE (AOV) ---
    paid_invoice_count = Invoice.query.filter(Invoice.status == 'Paid').count()
    aov = (total_revenue / paid_invoice_count) if paid_invoice_count > 0 else 0

    # --- KPI 5: CUSTOMER SATISFACTION (CSAT) ---
    # Average of Review.rating (1-5 stars)
    avg_rating = db.session.query(func.avg(Review.rating)).scalar() or 0
    csat_score = round(avg_rating, 1)

    # --- KPI 6: CANCELLATION RATE ---
    # Percentage of orders marked as 'Cancelled'
    cancelled_count = Order.query.filter_by(status='Cancelled').count()
    cancel_rate = 0
    if total_orders > 0:
        cancel_rate = (cancelled_count / total_orders) * 100

    # --- CHART DATA ---
    monthly_data = db.session.query(
        extract('month', Invoice.date_created).label('month'), func.sum(Invoice.amount).label('total')
    ).filter(Invoice.status == 'Paid', extract('year', Invoice.date_created) == curr_year).group_by('month').all()

    chart_invoice_reality = [0] * 12
    for item in monthly_data:
        chart_invoice_reality[int(item.month) - 1] = item.total

    chart_invoice_target = get_sales_targets()

    # --- CATEGORY DATA ---
    category_data = db.session.query(Product.category, func.sum(Product.sales_count * Product.price).label('rev')).group_by(Product.category).all()
    chart_cat_labels = [row.category for row in category_data if row.category]
    chart_cat_data = [row.rev for row in category_data if row.category]

    # --- TABLES ---
    top_products = Product.query.order_by(Product.sales_count.desc()).limit(5).all()
    recent_orders = Order.query.order_by(Order.date_placed.desc()).limit(6).all()

    return render_template('dashboard.html',
        total_revenue=format_k(total_revenue), revenue_growth=revenue_growth,
        total_orders=total_orders, order_growth=order_growth,
        total_customers=total_customers,
        aov=format_k(aov),
        csat_score=csat_score,   # <--- NEW
        cancel_rate=cancel_rate, # <--- NEW
        
        chart_invoice_months=['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
        chart_invoice_reality=chart_invoice_reality, chart_invoice_target=chart_invoice_target,
        chart_cat_labels=chart_cat_labels, chart_cat_data=chart_cat_data,
        top_products=top_products, recent_orders=recent_orders
    )

@app.route('/update_targets', methods=['POST'])
@admin_required
def update_targets():
    try:
        new_targets = []
        months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
        for m in months:
            val_str = request.form.get(f'target_{m}', '0').lower().replace(',', '')
            val = float(val_str.replace('k', '')) * 1000 if 'k' in val_str else float(val_str.replace('m', '')) * 1000000 if 'm' in val_str else float(val_str)
            new_targets.append(val)
        save_sales_targets(new_targets)
        log_action('Admin', g.user.username, 'System Update', 'System', 'Sales Targets', 'Success', 'Updated Dashboard Targets')
        flash('Sales targets updated.', 'success')
    except Exception as e: flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('dashboard'))

# [In app.py] Replace the existing 'orders' route with this:

@app.route('/orders')
def orders():
    # 1. Security Check (Replaces @login_required)
    if not g.user or g.user.role == 'Customer': 
        return redirect(url_for('login'))

    # 2. Get Arguments
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search', '').strip()
    status_filter = request.args.get('status', 'All')
    sort_option = request.args.get('sort', 'date_desc')

    # 3. Base Query
    # Join Client to search names, outerjoin OrderItem to search products
    query = Order.query.join(Client).outerjoin(OrderItem).group_by(Order.id)

    # 4. Smart Search Logic
    if search_query:
        # Create a "clean" version for ID matching (e.g. "ORD-005" -> "5", "005" -> "5")
        import re
        clean_id_search = re.sub(r'[^0-9]', '', search_query) # Remove non-digits
        
        search_filters = [
            Client.name.ilike(f'%{search_query}%'),      # Client Name
            Client.company.ilike(f'%{search_query}%'),   # Company
            OrderItem.item_name.ilike(f'%{search_query}%'), # Product Name
            Order.order_code.ilike(f'%{search_query}%')  # Standard Code match
        ]
        
        # If the user typed a number (like "5" or "123"), explicitly try to match the ID
        if clean_id_search:
            search_filters.append(Order.order_code.ilike(f'%ORD-{clean_id_search.zfill(3)}%')) 
            search_filters.append(Order.order_code.ilike(f'%{clean_id_search}%')) 
            
        query = query.filter(or_(*search_filters))

    # 5. Status Filter (Shipped vs Not Shipped)
    if status_filter == 'Shipped':
        query = query.filter(Order.status == 'Shipped')
    elif status_filter == 'Not Shipped':
        query = query.filter(Order.status != 'Shipped')

    # 6. Sorting Logic
    if sort_option == 'items_asc':
        # Sort by Quantity of Items
        query = query.order_by(func.sum(OrderItem.quantity).asc())
    elif sort_option == 'total_high':
        # Highest Total Amount
        query = query.order_by(Order.amount.desc())
    elif sort_option == 'total_low':
        # Lowest Total Amount
        query = query.order_by(Order.amount.asc())
    else:
        # Default: Newest First
        query = query.order_by(Order.date_placed.desc())

    # 7. Pagination
    orders_pagination = query.paginate(page=page, per_page=10, error_out=False)

    return render_template('orders.html', orders=orders_pagination)

@app.route('/invoices')
def invoices():
    if not g.user or g.user.role == 'Customer': return redirect(url_for('login'))
    
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    status_filter = request.args.get('status', 'All')
    sort_by = request.args.get('sort', 'date_desc')
    
    query = Invoice.query
    
    # 1. Search Logic (Search by Invoice Code or Client Name)
    if search:
        query = query.join(Client).filter(
            or_(
                Invoice.invoice_code.ilike(f'%{search}%'),
                Client.name.ilike(f'%{search}%')
            )
        )
    
    # 2. Filter Logic (Paid, Pending, Cancelled, Expired)
    if status_filter != 'All':
        query = query.filter(Invoice.status == status_filter)
        
    # 3. Sort Logic
    if sort_by == 'date_asc':
        query = query.order_by(Invoice.date_created.asc())
    elif sort_by == 'amount_high':
        query = query.order_by(Invoice.amount.desc())
    elif sort_by == 'amount_low':
        query = query.order_by(Invoice.amount.asc())
    else: # date_desc (Default)
        query = query.order_by(Invoice.date_created.desc())
        
    invoices_pagination = query.paginate(page=page, per_page=10, error_out=False)
    
    return render_template('invoices.html', invoices=invoices_pagination)

@app.route('/invoice/create/<int:order_id>', methods=['GET', 'POST'])
@admin_required
def create_invoice(order_id):
    order = Order.query.get_or_404(order_id)
    
    # Prevent duplicate invoices
    if order.invoice:
        flash("Order already has an invoice.", "warning")
        return redirect(url_for('view_invoice', invoice_id=order.invoice.id))
        
    if request.method == 'POST':
        try:
            invoice_code = f"INV-{datetime.now().strftime('%Y%m%d')}-{random.randint(1000, 9999)}"
            new_invoice = Invoice(
                invoice_code=invoice_code,
                order_id=order.id,
                client_id=order.client_id,
                amount=order.amount,
                status='Pending',
                date_due=datetime.strptime(request.form['date_due'], '%Y-%m-%d')
            )
            
            order.status = 'Invoiced'
            db.session.add(new_invoice)
            db.session.commit()
            
            log_action('Admin', g.user.username, 'Created Invoice', 'Invoice', invoice_code, 'Success', f'For Order {order.order_code}')
            flash("Invoice generated successfully.", "success")
            return redirect(url_for('view_invoice', invoice_id=new_invoice.id))
            
        except Exception as e:
            db.session.rollback()
            flash(f"Error creating invoice: {str(e)}", "danger")
            
    # Default due date: 7 days from now
    default_due_date = (datetime.now() + timedelta(days=7)).strftime('%Y-%m-%d')
    return render_template('create_invoice.html', order=order, default_due_date=default_due_date)

@app.route('/invoice/view/<int:invoice_id>')
def view_invoice(invoice_id):
    if not g.user: return redirect(url_for('login'))
    
    invoice = Invoice.query.get_or_404(invoice_id)
    
    # 1. Customer Logic: Strict Ownership Check & Customer Layout
    if g.user.role == 'Customer':
        client = Client.query.filter_by(email=g.user.email).first()
        
        # Security: If invoice doesn't belong to this client, kick them out
        if not client or invoice.client_id != client.id:
            flash("Access Denied: You can only view your own invoices.", "danger")
            return redirect(url_for('store_home'))
            
        # Render with CUSTOMER layout (No Admin Panel)
        return render_template('view_invoice.html', invoice=invoice, is_customer_view=True)
            
    # 2. Admin Logic: Admin Layout
    return render_template('view_invoice.html', invoice=invoice, is_customer_view=False)

@app.route('/invoice/edit/<int:invoice_id>', methods=['GET', 'POST'])
@admin_required
def edit_invoice(invoice_id):
    invoice = Invoice.query.get_or_404(invoice_id)
    
    if request.method == 'POST':
        new_status = request.form['status']
        old_status = invoice.status
        
        # 1. Update Invoice Details
        invoice.status = new_status
        invoice.date_due = datetime.strptime(request.form['date_due'], '%Y-%m-%d')
        
        # 2. SYNC LOGIC: If Cancelled, update Order & Restock
        if new_status == 'Cancelled' and old_status != 'Cancelled':
            if invoice.order:
                # This status change effectively "removes" it from the Orders List query
                invoice.order.status = 'Cancelled'
                
                # Restore Stock
                for item in invoice.order.items:
                    prod = Product.query.filter_by(name=item.item_name).first()
                    if prod:
                        prod.stock += item.quantity
                        prod.sales_count -= item.quantity
                        
        # 3. REACTIVATION LOGIC: If un-cancelling, set order back to active
        elif new_status in ['Paid', 'Invoiced'] and old_status == 'Cancelled':
            if invoice.order:
                invoice.order.status = 'Invoiced' # Puts it back in the list
                
                # Re-deduct Stock
                for item in invoice.order.items:
                    prod = Product.query.filter_by(name=item.item_name).first()
                    if prod:
                        prod.stock -= item.quantity
                        prod.sales_count += item.quantity

        db.session.commit()
        
        log_action('Admin', g.user.username, 'Edited Invoice', 'Invoice', invoice.invoice_code, 'Success', f'Status: {invoice.status}')
        flash("Invoice updated.", "success")
        return redirect(url_for('view_invoice', invoice_id=invoice.id))
        
    return render_template('edit_invoice.html', invoice=invoice)

@app.route('/invoice/delete/<int:invoice_id>', methods=['POST'])
@admin_required
def delete_invoice(invoice_id):
    try:
        invoice = Invoice.query.get_or_404(invoice_id)
        # Reset order status
        if invoice.order:
            invoice.order.status = 'Pending'
            
        db.session.delete(invoice)
        db.session.commit()
        flash("Invoice deleted.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error: {str(e)}", "danger")
        
    return redirect(url_for('invoices'))

# app.py

@app.route('/invoice/log_download/<int:invoice_id>', methods=['POST'])
def log_invoice_download(invoice_id):
    # Security: User must be logged in
    if not g.user: 
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
    
    try:
        invoice = Invoice.query.get_or_404(invoice_id)
        
        # Security: Customer can only log their own invoices
        if g.user.role == 'Customer':
            client = Client.query.filter_by(email=g.user.email).first()
            if not client or invoice.client_id != client.id:
                return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403

        # Log the action
        log_action(
            actor_type='User', 
            actor_id=g.user.username, 
            action='Downloaded Invoice', 
            entity_type='Invoice', 
            entity_id=invoice.invoice_code, 
            status='Success', 
            description='PDF Download Generated'
        )
        
        return jsonify({'status': 'success'})

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# [REPLACE THE 'audit_log' ROUTE IN app.py]

@app.route('/audit')
def audit_log():
    if not g.user or g.user.role == 'Customer': return redirect(url_for('login'))
    
    # 1. Get Filter Parameters
    page = request.args.get('page', 1, type=int)
    search_q = request.args.get('q', '').strip()
    action_filter = request.args.get('action_type', 'All')
    actor_filter = request.args.get('actor_type', 'All')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    query = AuditLog.query
    
    # 2. Apply Search Filter (Searches Description, IDs, or Action names)
    if search_q:
        query = query.filter(
            or_(
                AuditLog.description.ilike(f'%{search_q}%'),
                AuditLog.actor_id.ilike(f'%{search_q}%'),
                AuditLog.entity_id.ilike(f'%{search_q}%'),
                AuditLog.action.ilike(f'%{search_q}%')
            )
        )
        
    # 3. Apply Dropdown Filters
    if action_filter != 'All':
        query = query.filter(AuditLog.action == action_filter)
        
    if actor_filter != 'All':
        query = query.filter(AuditLog.actor_type == actor_filter)

    # 4. Apply Date Range Filter
    if start_date:
        try:
            s_date = datetime.strptime(start_date, '%Y-%m-%d')
            query = query.filter(AuditLog.timestamp >= s_date)
        except: pass
        
    if end_date:
        try:
            # Add 1 day to include the end date fully (up to 23:59:59)
            e_date = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(AuditLog.timestamp < e_date)
        except: pass
        
    # 5. Order & Paginate
    query = query.order_by(AuditLog.timestamp.desc())
    logs_pagination = query.paginate(page=page, per_page=15, error_out=False)
    
    # 6. Fetch Unique Values for Dropdowns
    unique_actions = [r.action for r in db.session.query(AuditLog.action).distinct()]
    unique_actors = [r.actor_type for r in db.session.query(AuditLog.actor_type).distinct()]
    
    return render_template('audit_log.html', 
                           logs=logs_pagination, 
                           unique_actions=unique_actions, 
                           unique_actors=unique_actors)

@app.route('/audit/view/<int:log_id>')
def audit_details(log_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    log = AuditLog.query.get_or_404(log_id)
    return render_template('audit_details.html', log=log)

# [REPLACE THE EXISTING 'admin_panel' ROUTE IN app.py]

# [REPLACE IN app.py]

@app.route('/admin/panel')
@admin_required
def admin_panel():
    settings = get_system_settings()
    
    # Search Logic
    search_q = request.args.get('q')
    
    if search_q:
        # Filter Staff
        staff_users = User.query.filter(
            User.role != 'Customer', 
            or_(User.username.ilike(f'%{search_q}%'), User.custom_id.ilike(f'%{search_q}%'))
        ).all()
        
        # Filter Customers
        customer_users = User.query.filter(
            User.role == 'Customer',
            or_(User.email.ilike(f'%{search_q}%'), User.first_name.ilike(f'%{search_q}%'), User.custom_id.ilike(f'%{search_q}%'))
        ).all()
    else:
        # Default: Fetch ALL Staff vs ALL Customers
        staff_users = User.query.filter(User.role != 'Customer').all()
        customer_users = User.query.filter_by(role='Customer').all()

    # CRITICAL: Sending 'staff_users' and 'customer_users' to match the new HTML
    return render_template('admin_panel.html', 
                           staff_users=staff_users, 
                           customer_users=customer_users, 
                           show_passwords=settings.get('show_passwords'))

@app.route('/admin/create', methods=['GET', 'POST'])
@admin_required
def create_admin():
    if request.method == 'POST':
        try:
            # 1. Check for duplicate username BEFORE trying to save
            if User.query.filter_by(username=request.form['username']).first():
                flash("Username already taken.", "danger")
                return redirect(url_for('create_admin'))

            count = User.query.count() + 1
            custom_id = f"USR-{datetime.now().year}-{count:03d}"
            
            new_user = User(
                custom_id=custom_id, 
                username=request.form['username'], 
                password=request.form['password'], 
                role=request.form['role'], 
                must_change_password=True
            )
            db.session.add(new_user)
            db.session.commit()
            log_action('Admin', g.user.username, 'Create User', 'User', new_user.username, 'Success', f'Created {new_user.role}')
            flash("New staff account created successfully.", "success")
            return redirect(url_for('admin_panel'))
            
        except Exception as e:
            # 2. CRITICAL FIX: Rollback transaction to prevent "PendingRollbackError"
            db.session.rollback()
            flash(f"Error creating account: {str(e)}", "danger")
            
    return render_template('admin_create.html')
@app.route('/admin/edit/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_admin(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        if request.form.get('admin_password') != g.user.password:
            flash("Incorrect password.", "danger")
            return redirect(url_for('edit_admin', user_id=user.id))
        user.role = request.form['role']
        db.session.commit()
        log_action('Admin', g.user.username, 'Edit User', 'User', user.username, 'Success', f'Changed role to {user.role}')
        return redirect(url_for('admin_panel'))
    return render_template('admin_edit.html', user=user)

@app.route('/admin/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_admin(user_id):
    try:
        user = User.query.get_or_404(user_id)
        target_name = user.username  # Fix: Capture the name BEFORE deleting the object
        
        # 1. Clean up dependencies (Fixes Database Integrity Errors)
        # If we don't delete these first, the database blocks the user deletion
        PaymentMethod.query.filter_by(user_id=user.id).delete()
        Review.query.filter_by(user_id=user.id).delete()
        
        # 2. Delete the User
        db.session.delete(user)
        db.session.commit()
        
        # 3. Log and Notify
        log_action('Admin', g.user.username, 'Delete User', 'User', target_name, 'Success', 'Deleted Account')
        flash(f"User {target_name} has been successfully deleted.", "success")
        
    except Exception as e:
        db.session.rollback()
        # Fix: Now we actually see the error if something goes wrong
        flash(f"Error deleting user: {str(e)}", "danger")
        print(f"Delete Error: {str(e)}")
        
    return redirect(url_for('admin_panel'))

@app.route('/logout')
def logout():
    if g.user:
        log_action('Admin', g.user.username, 'Logout', 'Auth', 'N/A', 'Success', 'Admin Logged Out')
    session.clear()
    return redirect(url_for('login'))

@app.route('/generate_bulk_data')
@operator_required
def generate_bulk_data():
    try:
        client = Client(name="Demo Client", email="demo@test.com", company="Demo Corp")
        db.session.add(client)
        db.session.commit()
        flash("Generated dummy client.", "success")
    except: pass
    return redirect(url_for('dashboard'))

@app.route('/guide')
def guide(): return render_template('guide.html')

@app.route('/error')
def error_page(): return render_template('error.html')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session: return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        new_pw = request.form.get('new_password')
        email_input = request.form.get('email')
        
        # 1. Enforce Email Requirement
        if not user.email and not email_input:
            flash("You must register a recovery email address to continue.", "danger")
            return render_template('change_password.html', user=user, email_required=True)
            
        # 2. Prevent Password Reuse (Current & History)
        
        # A. Check against the CURRENT (Temp) Password
        # If user.password is plain text (temp)
        if user.password == new_pw: 
            flash("You cannot reuse your temporary password.", "danger")
            return render_template('change_password.html', user=user, email_required=(not user.email))
            
        # If user.password is hashed (unlikely in this specific flow, but good practice)
        if user.password.startswith('scrypt:') and check_password_hash(user.password, new_pw):
            flash("You cannot reuse your current password.", "danger")
            return render_template('change_password.html', user=user, email_required=(not user.email))

        # B. Check against HISTORY (The Fix)
        # Fetch last 5 passwords
        past_passwords = PasswordHistory.query.filter_by(user_id=user.id).all()
        for record in past_passwords:
            if check_password_hash(record.password_hash, new_pw):
                flash("You cannot reuse a previously used password.", "danger")
                return render_template('change_password.html', user=user, email_required=(not user.email))

        # 3. Validate Password Strength
        valid, msg = is_password_strong(new_pw)
        if not valid:
            flash(f"Weak Password: {msg}", "danger")
            return render_template('change_password.html', user=user, email_required=(not user.email))

        # 4. Save Updates
        if email_input:
            user.email = email_input
            
        # Generate new hash
        new_hash = generate_password_hash(new_pw)
        
        # Archive the NEW password immediately so it's in history for next time
        db.session.add(PasswordHistory(user_id=user.id, password_hash=new_hash))
        
        user.password = new_hash
        user.must_change_password = False
        db.session.commit()
        
        flash("Account setup complete! You are now logged in.", "success")
        return redirect(url_for('dashboard'))
        
    # If user has no email, force them to enter it
    force_email = (user.email is None or user.email == '')
    return render_template('change_password.html', user=user, email_required=force_email)


@app.route('/admin/suspend/<int:user_id>', methods=['POST'])
@admin_required
def suspend_admin(user_id):
    user = User.query.get_or_404(user_id)
    
    # Logic: "Unsuspend" action requires SuperAdmin
    if user.is_suspended:
        # We are trying to ACTIVATE the user
        if g.user.role != 'SuperAdmin':
            flash("Access Denied: Only SuperAdmins can unsuspend accounts.", "danger")
            return redirect(url_for('admin_panel'))
            
        user.is_suspended = False
        user.failed_attempts = 0 # Reset attempts on unlock
        flash(f"User {user.username} has been unsuspended.", "success")
        
    else:
        # We are trying to SUSPEND the user
        if user.role == 'SuperAdmin':
            flash("You cannot suspend a SuperAdmin.", "danger")
            return redirect(url_for('admin_panel'))
            
        user.is_suspended = True
        flash(f"User {user.username} has been suspended.", "warning")

    db.session.commit()

    # --- ADD THIS LOGGING BLOCK ---
    status_str = "Suspended" if user.is_suspended else "Unsuspended"
    log_action('Admin', g.user.username, 'Suspend User', 'User', user.username, 'Success', f'{status_str} Account')

    return redirect(url_for('admin_panel'))

@app.route('/admin/danger_zone', methods=['GET', 'POST'])
@admin_required
def danger_zone():
    if request.method == 'POST':
        return redirect(url_for('danger_zone'))
    return render_template('danger_zone.html', days_skipped=0, show_passwords=False, email_required=False)

@app.route('/order/shipped/<int:order_id>', methods=['POST'])
@admin_required
def mark_shipped(order_id):
    order = Order.query.get_or_404(order_id)
    order.status = 'Shipped'
    db.session.commit()
    
    log_action('Admin', g.user.username, 'Fulfillment', 'Order', order.order_code, 'Success', 'Marked as Shipped')
    flash(f"Order {order.order_code} marked as Shipped.", "success")
    return redirect(url_for('orders'))

# ==============================================================================
# SECTION 8: MAIN EXECUTION
# ==============================================================================
if __name__ == '__main__':
    with app.app_context():
        try:
            with db.engine.connect() as conn:
                try: conn.execute(text("ALTER TABLE user ADD COLUMN first_name VARCHAR(50)"))
                except: pass
                try: conn.execute(text("ALTER TABLE user ADD COLUMN last_name VARCHAR(50)"))
                except: pass
                try: conn.execute(text("ALTER TABLE user ADD COLUMN phone VARCHAR(20)"))
                except: pass
                try: conn.execute(text("ALTER TABLE user ADD COLUMN gender VARCHAR(20)"))
                except: pass
                try: conn.execute(text("ALTER TABLE user ADD COLUMN auth_provider VARCHAR(20)"))
                except: pass
                try: conn.execute(text("ALTER TABLE user ADD COLUMN otp VARCHAR(6)"))
                except: pass
                try: conn.execute(text("ALTER TABLE user ADD COLUMN otp_expiry DATETIME"))
                except: pass
                try: conn.execute(text("ALTER TABLE user ADD COLUMN profile_image VARCHAR(200)"))
                except: pass
                try: conn.execute(text("ALTER TABLE user ADD COLUMN new_email_temp VARCHAR(120)"))
                except: pass
                try: conn.execute(text("ALTER TABLE user ADD COLUMN new_password_temp VARCHAR(100)"))
                except: pass
                try: conn.execute(text("ALTER TABLE user ADD COLUMN is_verified BOOLEAN"))
                except: pass
                try: 
                    conn.execute(text("""
                        CREATE TABLE IF NOT EXISTS payment_method (
                            id INTEGER PRIMARY KEY,
                            user_id INTEGER NOT NULL,
                            card_type VARCHAR(20),
                            last4 VARCHAR(4),
                            expiry VARCHAR(7),
                            FOREIGN KEY(user_id) REFERENCES user(id)
                        )
                    """))
                except: pass
                try: conn.execute(text("ALTER TABLE payment_method ADD COLUMN cardholder_name VARCHAR(100)"))
                except: pass
        except: pass
        
        db.create_all()

                # --- SEED PRODUCTS ---
        try:
            seed_products()
        except Exception as e:
            print(f"Seeding Error: {e}")
        # ---------------------
        # --- REMOVED CLEANUP TASK TO PREVENT DELETION ---

        # Ensure Default Admin Exists
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', password='password123', role='SuperAdmin', custom_id='USR-ADMIN-001')
            db.session.add(admin)
            db.session.commit()
            
    app.run(debug=True)