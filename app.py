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

# 4. Email Configuration
app.config['SMTP_SERVER'] = 'smtp.gmail.com'
app.config['SMTP_EMAIL'] = 'limjiaan41@gmail.com'.strip()
app.config['SMTP_PASSWORD'] = 'xfxx kqbw mrsv wsvc'.strip()

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
    
    if not sender_email or not sender_password:
        print(f"\n[DEV MODE - OTP] To: {user_email} | Code: {otp_code}\n")
        return True
        
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
    sender_email = app.config.get('SMTP_EMAIL')
    sender_password = app.config.get('SMTP_PASSWORD')
    smtp_server = app.config.get('SMTP_SERVER')
    if not sender_email or not sender_password: return False, "Missing credentials"
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = user_email
    msg['Subject'] = "Security Notice: Temporary Password Reset"
    body = f"Your temp password is: {temp_password}"
    msg.attach(MIMEText(body, 'plain'))
    try:
        server = smtplib.SMTP(smtp_server, 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, user_email, msg.as_string())
        server.quit()
        return True, "Sent"
    except Exception as e:
        return False, "Failed"

def is_password_strong(password):
    if len(password) < 8: return False, "Password must be at least 8 characters."
    if not re.search(r"[A-Z]", password): return False, "Password must contain an uppercase letter."
    if not re.search(r"\d", password): return False, "Password must contain a number."
    return True, "Valid"

@app.before_request
def load_user():
    g.user = None
    if 'user_id' in session: 
        try: g.user = User.query.get(session['user_id'])
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
    image_url = db.Column(db.String(200))
    description = db.Column(db.String(500))
    stock = db.Column(db.Integer, default=100)
    sales_count = db.Column(db.Integer, default=0)
    sizes = db.Column(db.String(200))

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False) # 1-5
    comment = db.Column(db.Text)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='reviews')
    order = db.relationship('Order', backref=db.backref('review', uselist=False))

# ==============================================================================
# SECTION 5: HELPER FUNCTIONS
# ==============================================================================
def log_action(actor_type, actor_id, action, entity_type, entity_id, status, description):
    try:
        log = AuditLog(actor_type=actor_type, actor_id=actor_id, action=action, entity_type=entity_type, entity_id=entity_id, status=status, description=description)
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Logging Failed: {e}")
def seed_products():
    """Adds dummy products to the database if none exist."""
    if Product.query.count() == 0:
        print("Seeding Database with Products...")
        products = [
            Product(
                name="Classic White Tee", 
                price=29.90, 
                category="Casual", 
                image_url="https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?ixlib=rb-4.0.3&auto=format&fit=crop&w=800&q=80",
                description="A staple for every wardrobe. Made from 100% organic cotton.",
                stock=50, sizes="S,M,L,XL"
            ),
            Product(
                name="Urban Denim Jacket", 
                price=89.00, 
                category="Casual", 
                image_url="https://images.unsplash.com/photo-1551537482-f2075a1d41f2?ixlib=rb-4.0.3&auto=format&fit=crop&w=800&q=80",
                description="Vintage wash denim jacket with a modern fit.",
                stock=30, sizes="M,L,XL"
            ),
            Product(
                name="Oxford Button-Down", 
                price=59.50, 
                category="Formal", 
                image_url="https://images.unsplash.com/photo-1598033129183-c4f50c736f10?ixlib=rb-4.0.3&auto=format&fit=crop&w=800&q=80",
                description="Crisp, clean, and professional. Perfect for the office.",
                stock=40, sizes="S,M,L,XL"
            ),
            Product(
                name="Slim Fit Chinos", 
                price=49.90, 
                category="Formal", 
                image_url="https://images.unsplash.com/photo-1624378439575-d8705ad7ae80?ixlib=rb-4.0.3&auto=format&fit=crop&w=800&q=80",
                description="Versatile chinos that work for both casual and formal occasions.",
                stock=45, sizes="30,32,34,36"
            ),
            Product(
                name="Minimalist Sneakers", 
                price=120.00, 
                category="Shoes", 
                image_url="https://images.unsplash.com/photo-1560769629-975ec94e6a86?ixlib=rb-4.0.3&auto=format&fit=crop&w=800&q=80",
                description="Clean lines and premium leather for everyday comfort.",
                stock=25, sizes="US 8,9,10,11"
            ),
            Product(
                name="Leather Weekender", 
                price=195.00, 
                category="Accessories", 
                image_url="https://images.unsplash.com/photo-1553062407-98eeb64c6a62?ixlib=rb-4.0.3&auto=format&fit=crop&w=800&q=80",
                description="The perfect bag for short trips. Durable and stylish.",
                stock=15, sizes="One Size"
            ),
            Product(
                name="Summer Floral Dress", 
                price=79.00, 
                category="Casual", 
                image_url="https://images.unsplash.com/photo-1572804013309-59a88b7e92f1?ixlib=rb-4.0.3&auto=format&fit=crop&w=800&q=80",
                description="Lightweight and breezy, perfect for warm weather.",
                stock=35, sizes="S,M,L"
            ),
            Product(
                name="Classic Chelsea Boots", 
                price=145.00, 
                category="Shoes", 
                image_url="https://images.unsplash.com/photo-1638247025967-b4e38f787b76?ixlib=rb-4.0.3&auto=format&fit=crop&w=800&q=80",
                description="Timeless style with durable construction.",
                stock=20, sizes="US 8,9,10,11"
            )
        ]
        db.session.add_all(products)
        db.session.commit()
        print("Products Added!")

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
            if user.role != 'Customer':
                flash("Staff members must use the Admin Login Portal.", "warning")
                return redirect(url_for('login'))
                
            # EXISTING CUSTOMER: Default to OTP
            otp = f"{random.randint(100000, 999999)}"
            user.otp = otp
            user.otp_expiry = datetime.utcnow() + timedelta(minutes=10)
            db.session.commit()
            
            send_otp_email(email, otp)
            print(f"\n[LOGIN OTP] Code for {email}: {otp}\n")
            
            session['pending_user_id'] = user.id
            return redirect(url_for('store_verify'))
        else:
            return redirect(url_for('store_signup_details'))
            
    return render_template('store_auth.html')

@app.route('/store/login/password', methods=['GET', 'POST'])
def store_login_password():
    """Allows customers to log in using a password instead of OTP."""
    if g.user: return redirect(url_for('store_home'))

    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.role == 'Customer':
            # Check password hash OR plain text (legacy support)
            is_correct = False
            if user.password.startswith('scrypt:'):
                is_correct = check_password_hash(user.password, password)
            else:
                is_correct = (user.password == password)

            if is_correct:
                session['user_id'] = user.id
                flash(f"Welcome back, {user.first_name}!", "success")
                return redirect(url_for('store_home'))
            else:
                flash("Incorrect password.", "danger")
        else:
            flash("Account not found. Please sign up.", "warning")
            
    return render_template('store_login.html')

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
            # --- FIX: ROBUST ID GENERATION START ---
            # Instead of counting, we look for the LAST used ID and add 1
            last_cust = User.query.filter(User.custom_id.like('CUST-%')).order_by(User.id.desc()).first()

            if last_cust and last_cust.custom_id:
                try:
                    # Extract the last number (e.g. from 'CUST-2026-005' get '005')
                    last_num = int(last_cust.custom_id.split('-')[-1])
                    new_num = last_num + 1
                except ValueError:
                    # Fallback if format is weird
                    new_num = User.query.count() + 1
            else:
                # First customer ever
                new_num = 1

            custom_id = f"CUST-{datetime.now().year}-{new_num:03d}"
            # --- FIX END ---
            
            # Hash Password for Professional Security
            hashed_pw = generate_password_hash(password)
            
            otp = f"{random.randint(100000, 999999)}"
            
            # STRICTLY CREATE AS CUSTOMER ROLE
            new_user = User(
                custom_id=custom_id, username=email, email=email, 
                password=hashed_pw, 
                first_name=first_name, last_name=last_name, phone=phone, gender=gender,
                role='Customer', auth_provider='local', otp=otp,
                otp_expiry=datetime.utcnow() + timedelta(minutes=10),
                is_verified=False 
            )
            db.session.add(new_user)
            db.session.commit()
            
            send_otp_email(email, otp)
            print(f"\n[SIGNUP OTP] Code for {email}: {otp}\n")
            
            session['pending_user_id'] = new_user.id 
            return redirect(url_for('store_verify'))
            
        except Exception as e:
            db.session.rollback()
            # Added better logging so you can see what failed
            print(f"Signup Error: {e}") 
            flash(f"System Error: {str(e)}", "danger")
            return render_template('store_signup.html', email=email, form_data=request.form)
            
    return render_template('store_signup.html', email=email, form_data={})

@app.route('/store/verify', methods=['GET', 'POST'])
def store_verify():
    pending_id = session.get('pending_user_id')
    email = session.get('auth_email')
    
    if not pending_id:
        return redirect(url_for('store_auth'))
        
    user = User.query.get(pending_id)
    if not user: return redirect(url_for('store_auth'))
    
    # Check if this is a new signup (Unverified) or existing login
    is_new_signup = not user.is_verified

    if request.method == 'POST':
        # --- OTP SUBMISSION ---
        if 'otp' in request.form:
            otp_input = request.form.get('otp')
            if user.otp == otp_input and user.otp_expiry > datetime.utcnow():
                user.otp = None
                user.is_verified = True
                db.session.commit()
                
                session['user_id'] = user.id
                session.pop('auth_email', None)
                session.pop('pending_user_id', None)
                
                flash(f"Welcome back, {user.first_name}!", "success")
                return redirect(url_for('store_home')) 
            else:
                flash("Invalid or expired code. Please try again.", "danger")

        # --- PASSWORD SUBMISSION (Existing Users Only) ---
        elif 'password' in request.form:
            if is_new_signup:
                flash("Please verify your email with the code first.", "warning")
            else:
                password = request.form.get('password')
                # Check password hash OR plain text (legacy support)
                is_correct = False
                if user.password.startswith('scrypt:'):
                    is_correct = check_password_hash(user.password, password)
                else:
                    is_correct = (user.password == password)

                if is_correct:
                    # Clear OTP if they used password
                    user.otp = None
                    db.session.commit()
                    
                    session['user_id'] = user.id
                    session.pop('auth_email', None)
                    session.pop('pending_user_id', None)
                    
                    flash(f"Welcome back, {user.first_name}!", "success")
                    return redirect(url_for('store_home'))
                else:
                    flash("Incorrect password.", "danger")
            
    return render_template('store_verify.html', email=user.email, is_new_signup=is_new_signup)

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
            count = User.query.count() + 1
            custom_id = f"CUST-{datetime.now().year}-{count:03d}"
            user = User(
                custom_id=custom_id, username=email, email=email,
                # We use a specific placeholder to identify users who haven't set a password yet
                password="GOOGLE_OAUTH_USER", 
                first_name=first_name, last_name=last_name,
                role='Customer', auth_provider='google', is_verified=True
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
                custom_id=custom_id, username=email, email=email,
                password="DISCORD_OAUTH_USER", 
                first_name=first_name, last_name=last_name,
                role='Customer', auth_provider='discord', is_verified=True
            )
            db.session.add(user)
            db.session.commit()
            
            session['user_id'] = user.id
            flash("Account created via Discord!", "success")
            return redirect(url_for('store_setup_password'))
        
        if user.role != 'Customer':
            flash("Staff accounts cannot use Social Login.", "danger")
            return redirect(url_for('login'))

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
            # 2. Validate New Password Strength
            valid, msg = is_password_strong(new_pw)
            if not valid:
                flash(f"Security Error: {msg}", "danger")
            else:
                # 3. Generate OTP & Send Email
                otp = f"{random.randint(100000, 999999)}"
                g.user.new_password_temp = generate_password_hash(new_pw)
                g.user.otp = otp
                g.user.otp_expiry = datetime.utcnow() + timedelta(minutes=10)
                db.session.commit()
                
                # SEND EMAIL HERE
                send_otp_email(g.user.email, otp)
                print(f"\n[SECURITY OTP] Code for {g.user.email}: {otp}\n")
                
                flash(f"Verification code sent to {g.user.email}", "info")
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
    session.pop('show_email_verify', None)
    
    if g.user:
        g.user.otp = None
        g.user.new_password_temp = None
        g.user.new_email_temp = None
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
        session.pop('show_email_verify', None)
        flash("Email address updated successfully.", "success")
    else:
        flash("Invalid OTP.", "danger")
        session['show_email_verify'] = True
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
        product = Product.query.get(p_id)
        
        if product:
            cart = session['cart']
            p_id_str = str(p_id)
            if p_id_str in cart: 
                cart[p_id_str]['qty'] += qty
            else:
                cart[p_id_str] = {
                    'name': product.name, 
                    'price': product.price, 
                    'qty': qty, 
                    'image': product.image_url, 
                    'category': product.category
                }
            session.modified = True
            
            # --- AJAX RESPONSE (Prevents Page Refresh) ---
            # If the browser sent this via JS fetch/AJAX
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                cart_count = sum(item['qty'] for item in cart.values())
                return json.dumps({
                    'status': 'success', 
                    'cart_count': cart_count, 
                    'message': f'Added {product.name}'
                })
            
            # Fallback for non-JS browsers
            flash(f'Added {product.name} to cart!', 'success')
            return redirect(request.referrer or url_for('store_cart'))
        
    totals = calculate_cart_totals(session['cart'])
    cart_items = []
    for p_id, item in session['cart'].items():
        item['total'] = item['price'] * item['qty']
        item['id'] = p_id
        cart_items.append(item)
    return render_template('store_cart.html', cart_items=cart_items, totals=totals)

@app.route('/cart/update', methods=['POST'])
def update_cart():
    if 'cart' not in session: return redirect(url_for('store_cart'))
    p_id = str(request.form.get('product_id'))
    action = request.form.get('action')
    
    if p_id in session['cart']:
        if action == 'increase': session['cart'][p_id]['qty'] += 1
        elif action == 'decrease': session['cart'][p_id]['qty'] -= 1
        elif action == 'delete': del session['cart'][p_id]
        
        # Cleanup
        if p_id in session['cart'] and session['cart'][p_id]['qty'] <= 0: 
            del session['cart'][p_id]
            
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

            # 2. Capture Shipping (For Confirm Page Display Only - DB schema lacks address)
            shipping_info = {
                'first_name': request.form.get('first_name'),
                'last_name': request.form.get('last_name'),
                'address': request.form.get('address'),
                'city': request.form.get('city'),
                'zip': request.form.get('zip')
            }

            # 3. CREATE RECORDS IMMEDIATELY (Status: Pending)
            # Find/Create Client
            client = Client.query.filter_by(email=g.user.email).first()
            if not client:
                client = Client(name=f"{g.user.first_name} {g.user.last_name}", email=g.user.email, company="Online Customer")
                db.session.add(client)
                db.session.commit() # Commit to get ID

            # Create Order
            order_code = f"ORD-{datetime.now().strftime('%Y%m%d')}-{random.randint(1000,9999)}"
            # We append address to description since we don't have an address table
            full_desc = f"{payment_desc} | Ship to: {shipping_info['address']}"
            
            new_order = Order(
                order_code=order_code, 
                client_id=client.id,
                description=full_desc[:200], # Truncate if too long
                amount=totals['grand_total'], 
                status='Pending', # <--- Initially Pending
                date_placed=datetime.utcnow()
            )
            db.session.add(new_order)
            db.session.flush()

            # Create Order Items & Deduct Stock
            for p_id, item in session['cart'].items():
                order_item = OrderItem(order_id=new_order.id, item_name=item['name'], quantity=item['qty'], unit_price=item['price'], total_price=item['price']*item['qty'])
                db.session.add(order_item)
                
                # DEDUCT STOCK NOW
                prod = Product.query.get(int(p_id))
                if prod:
                    prod.stock -= item['qty']
                    prod.sales_count += item['qty']
            
            # Add Fees
            if totals['shipping'] > 0: 
                db.session.add(OrderItem(order_id=new_order.id, item_name="Shipping Fee", quantity=1, unit_price=totals['shipping'], total_price=totals['shipping']))
            if totals['gst'] > 0: 
                db.session.add(OrderItem(order_id=new_order.id, item_name="GST (9%)", quantity=1, unit_price=totals['gst'], total_price=totals['gst']))

            # Create Invoice (Pending)
            inv_code = f"INV-{datetime.now().strftime('%Y%m%d')}-{random.randint(100,999)}"
            new_invoice = Invoice(
                invoice_code=inv_code, 
                order_id=new_order.id, 
                client_id=client.id, 
                amount=totals['grand_total'], 
                status='Pending', # <--- Pending
                date_created=datetime.utcnow(), 
                date_due=datetime.utcnow() + timedelta(days=7) # Due in 7 days
            )
            db.session.add(new_invoice)
            db.session.commit()
            
            # 4. Save to Session for Confirmation Step
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
    
    # Optional: Fetch order if you want to display details (e.g. "Thanks, [Name]")
    order = Order.query.filter_by(order_code=order_code).first()
    
    return render_template('store_checkout_success.html', order_code=order_code, order=order)

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

@app.route('/product/<int:product_id>')
def store_product(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('store_product.html', product=product)

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

# ==============================================================================
# SECTION 7: ADMIN PANEL ROUTES (PRESERVED & FIXED LOGGING)
# ==============================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.password == password:
            # SEPARATION CHECK:
            # Ensure Customers cannot use the Admin Panel login
            if user.role == 'Customer':
                flash("Access Denied: Customers must use the Store Login.", "danger")
                return redirect(url_for('store_auth'))
            
            session['user_id'] = user.id
            log_action('Admin', user.username, 'Login', 'Auth', 'N/A', 'Success', 'Admin Panel Login')
            return redirect(url_for('dashboard'))
        flash("Invalid Admin Credentials", "danger")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if not g.user or g.user.role == 'Customer': return redirect(url_for('login'))
    total_orders=0; total_sales="0"; products_sold=0; new_customers=0
    order_growth=0; sales_growth=0; product_growth=0; customer_growth=0
    ytd_sales="0"; ytd_sales_growth="0"; ytd_pos=True
    ytd_count="0"; ytd_count_growth="0"; ytd_count_pos=True
    mtd_sales="0"; mtd_sales_diff="0"; mtd_pos=True
    mtd_count=0; mtd_count_diff=0; mtd_count_pos=True
    chart_invoice_reality = [0] * 12
    chart_invoice_target = get_sales_targets()
    chart_orders_ytd_pct = [50, 50]; chart_orders_mtd_pct = [50, 50]
    top_clients_progress = []; chart_vol_service_labels = []; chart_vol_data = []; chart_service_data = []
    chart_sat_labels = []; chart_sat_data = []
    try:
        total_orders = Order.query.count()
        total_sales = db.session.query(func.sum(Invoice.amount)).scalar() or 0
        products_sold = Invoice.query.filter_by(status='Paid').count()
        new_customers = Client.query.count()
    except Exception: pass
    
    return render_template('dashboard.html',
        total_orders=format_k(total_orders), order_growth=order_growth,
        total_sales=format_k(total_sales), sales_growth=sales_growth,
        products_sold=products_sold, product_growth=product_growth,
        new_customers=new_customers, customer_growth=customer_growth,
        ytd_sales=ytd_sales, ytd_sales_growth=ytd_sales_growth, ytd_pos=ytd_pos,
        ytd_count=ytd_count, ytd_count_growth=ytd_count_growth, ytd_count_pos=ytd_count_pos,
        mtd_sales=mtd_sales, mtd_sales_diff=mtd_sales_diff, mtd_pos=mtd_pos,
        mtd_count=mtd_count, mtd_count_diff=mtd_count_diff, mtd_count_pos=mtd_count_pos,
        chart_invoice_months=['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
        chart_invoice_reality=chart_invoice_reality, chart_invoice_target=chart_invoice_target,
        chart_orders_ytd_pct=chart_orders_ytd_pct, chart_orders_mtd_pct=chart_orders_mtd_pct,
        top_clients_progress=top_clients_progress,
        chart_vol_service_labels=chart_vol_service_labels, chart_vol_data=chart_vol_data, chart_service_data=chart_service_data,
        chart_sat_labels=chart_sat_labels, chart_sat_data=chart_sat_data
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
        flash('Sales targets updated.', 'success')
    except Exception as e: flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('dashboard'))

@app.route('/orders')
def orders():
    if not g.user or g.user.role == 'Customer': return redirect(url_for('login'))
    page = request.args.get('page', 1, type=int)
    query = Order.query.order_by(Order.date_placed.desc())
    orders_pagination = query.paginate(page=page, per_page=10, error_out=False)
    return render_template('orders.html', orders=orders_pagination)

@app.route('/invoices')
def invoices():
    if not g.user or g.user.role == 'Customer': return redirect(url_for('login'))
    page = request.args.get('page', 1, type=int)
    query = Invoice.query.order_by(Invoice.date_created.desc())
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
        invoice.status = request.form['status']
        invoice.date_due = datetime.strptime(request.form['date_due'], '%Y-%m-%d')
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

@app.route('/audit')
def audit_log():
    if not g.user or g.user.role == 'Customer': return redirect(url_for('login'))
    page = request.args.get('page', 1, type=int)
    logs_pagination = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=10, error_out=False)
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
    users = User.query.all()
    settings = get_system_settings()
    return render_template('admin_panel.html', users=users, show_passwords=settings.get('show_passwords'))

@app.route('/admin/create', methods=['GET', 'POST'])
@admin_required
def create_admin():
    if request.method == 'POST':
        try:
            count = User.query.count() + 1
            custom_id = f"USR-{datetime.now().year}-{count:03d}"
            # This allows creating admins with specific roles
            new_user = User(custom_id=custom_id, username=request.form['username'], password=request.form['password'], role=request.form['role'], must_change_password=True)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('admin_panel'))
        except: pass
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
        return redirect(url_for('admin_panel'))
    return render_template('admin_edit.html', user=user)

@app.route('/admin/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_admin(user_id):
    try:
        user = User.query.get(user_id)
        db.session.delete(user)
        db.session.commit()
    except: pass
    return redirect(url_for('admin_panel'))

@app.route('/logout')
def logout():
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
        user.password = request.form['new_password']
        user.must_change_password = False
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('change_password.html', user=user, email_required=False)

@app.route('/admin/reset_password/<int:user_id>', methods=['POST'])
@admin_required
def reset_password(user_id):
    user = User.query.get_or_404(user_id)
    user.password = request.form.get('temp_password')
    user.must_change_password = True
    db.session.commit()
    flash(f'Password reset for {user.username}.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/suspend/<int:user_id>', methods=['POST'])
@admin_required
def suspend_admin(user_id):
    user = User.query.get(user_id)
    user.is_suspended = not user.is_suspended
    db.session.commit()
    return redirect(url_for('admin_panel'))

@app.route('/admin/danger_zone', methods=['GET', 'POST'])
@admin_required
def danger_zone():
    if request.method == 'POST':
        return redirect(url_for('danger_zone'))
    return render_template('danger_zone.html', days_skipped=0, show_passwords=False, email_required=False)

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