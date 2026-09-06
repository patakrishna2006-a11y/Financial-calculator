from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import os
from dotenv import load_dotenv
import json
import re
import logging
import secrets
from logging.handlers import RotatingFileHandler
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail, Message

load_dotenv()

IST = ZoneInfo("Asia/Kolkata")

def now_ist():
    return datetime.now(IST)

from calculator import (
    SIP, LUMPSUM, SWP, STEP_UP_SIP, PPF, EPF, NSC,
    FD_SIMPLE, RD, NPS, RETIREMENT_CALCULATOR, GRATUITY,
    SALARY_CALCULATOR, EMI, HOME_LOAN_EMI, CAR_LOAN_EMI,
    GOLD_LOAN_EMI, EDUCATION_LOAN_EMI, FLAT_VS_REDUCING,
    SIMPLE_INTEREST, COMPOUND_INTEREST, GST, CAGR,
    INFLATION, BROKERAGE_CALCULATOR,
    format_indian_raw, PARAM_DECIMALS
)

app = Flask(__name__)

# --- Security Configuration ---
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise RuntimeError("FLASK_SECRET_KEY environment variable must be set")

# Database configuration - use PostgreSQL in production, SQLite for development
database_url = os.environ.get('DATABASE_URL')
if database_url:
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

# Session cookie security
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV', 'development') == 'production'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['SESSION_PERMANENT'] = True

# CSRF Configuration
app.config['WTF_CSRF_TIME_LIMIT'] = None
app.config['WTF_CSRF_SSL_STRICT'] = app.config['SESSION_COOKIE_SECURE']

db = SQLAlchemy(app)

# --- Initialize Extensions ---
csrf = CSRFProtect(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# --- Mail Configuration ---
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')
app.config['BASE_URL'] = os.environ.get('BASE_URL', 'http://localhost:5000')

mail = Mail(app)

# --- Security Logging Setup ---
security_logger = logging.getLogger('security')
security_logger.setLevel(logging.INFO)
if not security_logger.handlers:
    handler = RotatingFileHandler('security.log', maxBytes=10000, backupCount=3)
    handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    security_logger.addHandler(handler)

def log_security_event(event_type, details, user_id=None, ip=None):
    """Log security-relevant events."""
    ip = ip or request.remote_addr
    user_info = f"user_id={user_id}" if user_id else "anonymous"
    security_logger.info(f"{event_type} | ip={ip} | {user_info} | {details}")


def generate_verification_token():
    """Generate a secure random token for email verification."""
    return secrets.token_urlsafe(32)


def send_verification_email(user, token):
    """Send verification email to user."""
    verify_url = f"{app.config['BASE_URL']}/verify-email/{token}"
    
    html = render_template('email/verification.html',
        username=user.username,
        verify_url=verify_url,
        expiry_hours=1
    )
    
    msg = Message(
        subject="Verify your FinCalc Pro account",
        recipients=[user.email],
        html=html
    )
    mail.send(msg)


# --- Security Headers Middleware ---
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    # Content Security Policy
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    response.headers['Content-Security-Policy'] = csp
    
    # HSTS - only in production with HTTPS
    if app.config['SESSION_COOKIE_SECURE']:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Prevent MIME sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Referrer Policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Permissions Policy
    response.headers['Permissions-Policy'] = (
        'geolocation=(), microphone=(), camera=(), '
        'payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()'
    )
    
    # X-Frame-Options (backup for CSP frame-ancestors)
    response.headers['X-Frame-Options'] = 'DENY'
    
    # Cross-Origin policies
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    
    return response

# --- CSRF Error Handler ---
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    log_security_event('CSRF_FAILURE', f'reason={e.description}', ip=request.remote_addr)
    if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({"success": False, "error": "CSRF token missing or invalid"}), 400
    flash('Security token expired. Please try again.', 'danger')
    return redirect(url_for('home'))

# --- Custom Error Pages ---
@app.errorhandler(400)
def bad_request(e):
    log_security_event('BAD_REQUEST', str(e), ip=request.remote_addr)
    if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({"success": False, "error": "Bad request"}), 400
    return render_template('errors/400.html'), 400

@app.errorhandler(401)
def unauthorized(e):
    log_security_event('UNAUTHORIZED', str(e), ip=request.remote_addr)
    if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({"success": False, "error": "Authentication required"}), 401
    return redirect(url_for('login'))

@app.errorhandler(403)
def forbidden(e):
    log_security_event('FORBIDDEN', str(e), user_id=session.get('user_id'), ip=request.remote_addr)
    if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({"success": False, "error": "Access denied"}), 403
    return render_template('errors/403.html'), 403

@app.errorhandler(404)
def not_found(e):
    if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({"success": False, "error": "Not found"}), 404
    return render_template('errors/404.html'), 404

@app.errorhandler(405)
def method_not_allowed(e):
    log_security_event('METHOD_NOT_ALLOWED', f'{request.method} {request.path}', ip=request.remote_addr)
    if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({"success": False, "error": "Method not allowed"}), 405
    return render_template('errors/405.html'), 405

@app.errorhandler(413)
def payload_too_large(e):
    log_security_event('PAYLOAD_TOO_LARGE', f'content_length={request.content_length}', ip=request.remote_addr)
    if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({"success": False, "error": "Payload too large"}), 413
    return render_template('errors/413.html'), 413

@app.errorhandler(429)
def rate_limit_exceeded(e):
    log_security_event('RATE_LIMIT_EXCEEDED', f'{request.method} {request.path}', 
                       user_id=session.get('user_id'), ip=request.remote_addr)
    retry_after = getattr(e, 'retry_after', 60)
    if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        resp = jsonify({"success": False, "error": "Rate limit exceeded. Please try again later."})
        resp.headers['Retry-After'] = str(retry_after)
        return resp, 429
    return render_template('errors/429.html', retry_after=retry_after), 429

@app.errorhandler(500)
def internal_error(e):
    log_security_event('INTERNAL_ERROR', str(e), user_id=session.get('user_id'), ip=request.remote_addr)
    db.session.rollback()
    if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({"success": False, "error": "Internal server error"}), 500
    return render_template('errors/500.html'), 500

# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    verification_token = db.Column(db.String(100), unique=True, nullable=True)
    verification_token_expires = db.Column(db.DateTime, nullable=True)
    
    __table_args__ = (
        db.UniqueConstraint('username', 'email', name='_username_email_uc'),
    )

class CalculationHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    calc_type = db.Column(db.String(50), nullable=False)
    params = db.Column(db.Text, nullable=False)
    result = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=now_ist)

with app.app_context():
    db.create_all()

# --- Helper Functions ---
def format_json_data(json_str):
    try:
        data = json.loads(json_str)
        return ", ".join([f"{str(k).replace('_', ' ').title()}: {v}" for k, v in data.items()])
    except:
        return json_str

def validate_calculator_input(calc_type, params):
    """Validate calculator input parameters."""
    validators = {
        'SIP': lambda p: all(k in p for k in ['Monthly investment', 'Expected return', 'Years']),
        'LUMPSUM': lambda p: all(k in p for k in ['Total investment', 'Expected return', 'Years']),
        'SWP': lambda p: all(k in p for k in ['Total investment', 'Withdrawal amount', 'Expected rate', 'Years']),
        'STEP_UP_SIP': lambda p: all(k in p for k in ['Monthly investment', 'Step up rate', 'Expected return', 'Years']),
        'PPF': lambda p: all(k in p for k in ['Yearly investment', 'Annual interest rate', 'Years']),
        'EPF': lambda p: all(k in p for k in ['Basic salary', 'DA', 'Years of service', 'Annual salary growth', 'Epf interest rate']),
        'NSC': lambda p: all(k in p for k in ['Amount invested', 'Interest rate', 'Years']),
        'FD_SIMPLE': lambda p: all(k in p for k in ['Principal', 'Interest rate', 'Years']),
        'RD': lambda p: all(k in p for k in ['Monthly investment', 'Expected rate', 'Years']),
        'NPS': lambda p: all(k in p for k in ['Monthly investment', 'Annual return', 'Current age', 'Retirement age']),
        'RETIREMENT_CALCULATOR': lambda p: all(k in p for k in ['Age', 'Monthly expense', 'Retirement age', 'Life expectancy', 'Inflation', 'Annual return']),
        'GRATUITY': lambda p: all(k in p for k in ['Basic salary', 'DA', 'Years of service']),
        'SALARY_CALCULATOR': lambda p: all(k in p for k in ['CTC', 'Bonus', 'Professional tax', 'Employer pf', 'Employee pf', 'Other deductions']),
        'EMI': lambda p: all(k in p for k in ['Loan amount', 'Interest rate', 'Years']),
        'HOME_LOAN_EMI': lambda p: all(k in p for k in ['Loan amount', 'Interest rate', 'Years']),
        'CAR_LOAN_EMI': lambda p: all(k in p for k in ['Loan amount', 'Interest rate', 'Years']),
        'GOLD_LOAN_EMI': lambda p: all(k in p for k in ['Loan amount', 'Interest rate', 'Years']),
        'EDUCATION_LOAN_EMI': lambda p: all(k in p for k in ['Loan amount', 'Interest rate', 'Years']),
        'FLAT_VS_REDUCING': lambda p: all(k in p for k in ['Principal', 'Annual rate', 'Years']),
        'SIMPLE_INTEREST': lambda p: all(k in p for k in ['Principal amount', 'Rate of interest', 'Years']),
        'COMPOUND_INTEREST': lambda p: all(k in p for k in ['Principal amount', 'Interest rate', 'Years', 'Compounding_per_year']),
        'GST': lambda p: all(k in p for k in ['Original price', 'Gst rate']),
        'CAGR': lambda p: all(k in p for k in ['Initial value', 'Final value', 'Years']),
        'INFLATION': lambda p: all(k in p for k in ['Current price', 'Rate', 'Years']),
        'BROKERAGE_CALCULATOR': lambda p: all(k in p for k in ['Segment', 'Quantity', 'Buy price', 'Sell price', 'Brokerage']),
    }
    
    if calc_type not in validators:
        return False, f"Unknown calculator type: {calc_type}"
    
    if not validators[calc_type](params):
        return False, f"Missing required parameters for {calc_type}"
    
    # Validate numeric ranges
    # Skip non-numeric parameters
    non_numeric_keys = {'Segment', 'Mode', 'mode'}
    for key, value in params.items():
        if key in non_numeric_keys:
            continue
        try:
            num_val = float(value)
            if num_val < 0 and 'rate' not in key.lower() and 'return' not in key.lower() and 'growth' not in key.lower() and 'inflation' not in key.lower():
                return False, f"{key} cannot be negative"
            if key in ['Years', 'Years of service', 'Current age', 'Retirement age', 'Life expectancy', 'Age', 'Quantity', 'Compounding_per_year']:
                if num_val <= 0:
                    return False, f"{key} must be positive"
                if key in ['Current age', 'Retirement age', 'Life expectancy', 'Age'] and num_val > 120:
                    return False, f"{key} out of valid range"
            if 'rate' in key.lower() or 'return' in key.lower() or 'interest' in key.lower() or 'growth' in key.lower() or 'inflation' in key.lower():
                if num_val > 100:
                    return False, f"{key} percentage out of valid range"
        except (ValueError, TypeError):
            return False, f"Invalid value for {key}"
    
    return True, None

# --- Routes ---
@app.route('/')
def home():
    return render_template('landing.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute; 20 per hour")
def register():
    check_email = request.args.get('check_email', '0') == '1'
    
    if request.method == 'GET':
        return render_template('register.html', check_email=check_email)
    
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    # Input validation
    if not username or not email or not password or not confirm_password:
        log_security_event('REGISTRATION_FAILURE', 'missing_fields', ip=request.remote_addr)
        flash('All fields are required.', 'danger')
        return redirect(url_for('register'))
    
    if password != confirm_password:
        log_security_event('REGISTRATION_FAILURE', 'password_mismatch', ip=request.remote_addr)
        flash('Passwords do not match.', 'danger')
        return redirect(url_for('register'))
    
    if len(username) > 50:
        flash('Username too long.', 'danger')
        return redirect(url_for('register'))
    
    if len(email) > 100:
        flash('Email too long.', 'danger')
        return redirect(url_for('register'))
    
    # Email format validation
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        flash('Invalid email format.', 'danger')
        return redirect(url_for('register'))
    
    # Password complexity validation
    if len(password) < 9 or not re.search(r'[A-Za-z]', password) or not re.search(r'\d', password) or not re.search(r'[^A-Za-z0-9]', password):
        log_security_event('REGISTRATION_FAILURE', 'weak_password', ip=request.remote_addr)
        flash('Password must be at least 9 characters long and include a letter, a number, and a symbol.', 'danger')
        return redirect(url_for('register'))
    
    # Check if user already exists (unverified)
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        if existing_user.is_verified:
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        else:
            # Resend verification for unverified user
            token = generate_verification_token()
            existing_user.verification_token = token
            existing_user.verification_token_expires = now_ist() + timedelta(hours=1)
            db.session.commit()
            try:
                send_verification_email(existing_user, token)
                log_security_event('VERIFICATION_RESENT', f'username={username}', user_id=existing_user.id, ip=request.remote_addr)
            except Exception as e:
                log_security_event('VERIFICATION_EMAIL_FAILED', f'username={username} error={str(e)}', ip=request.remote_addr)
            return redirect(url_for('register', check_email=1))
    
    existing_email = User.query.filter_by(email=email).first()
    if existing_email:
        if existing_email.is_verified:
            flash('An account with this email already exists', 'danger')
            return redirect(url_for('register'))
        else:
            # Resend verification for unverified user
            token = generate_verification_token()
            existing_email.verification_token = token
            existing_email.verification_token_expires = now_ist() + timedelta(hours=1)
            db.session.commit()
            try:
                send_verification_email(existing_email, token)
                log_security_event('VERIFICATION_RESENT', f'email={email}', user_id=existing_email.id, ip=request.remote_addr)
            except Exception as e:
                log_security_event('VERIFICATION_EMAIL_FAILED', f'email={email} error={str(e)}', ip=request.remote_addr)
            return redirect(url_for('register', check_email=1))
    
    hashed_password = generate_password_hash(password)
    token = generate_verification_token()
    token_expires = now_ist() + timedelta(hours=1)
    
    new_user = User(
        username=username,
        password=hashed_password,
        email=email,
        is_verified=False,
        verification_token=token,
        verification_token_expires=token_expires
    )
    
    try:
        db.session.add(new_user)
        db.session.commit()
        log_security_event('REGISTRATION_SUCCESS', f'username={username}', user_id=new_user.id, ip=request.remote_addr)
        
        # Send verification email (non-blocking - log failure but don't fail registration)
        try:
            send_verification_email(new_user, token)
            log_security_event('VERIFICATION_EMAIL_SENT', f'username={username}', user_id=new_user.id, ip=request.remote_addr)
            flash('Verification email sent! Please check your inbox (valid for 1 hour).', 'success')
        except Exception as e:
            log_security_event('VERIFICATION_EMAIL_FAILED', f'username={username} error={str(e)}', user_id=new_user.id, ip=request.remote_addr)
            flash('Account created but verification email could not be sent. Use the "Resend" option on the next page.', 'warning')
        
        return redirect(url_for('register', check_email=1))
    except Exception as e:
        db.session.rollback()
        log_security_event('REGISTRATION_FAILURE', f'db_error={str(e)}', ip=request.remote_addr)
        flash('Registration failed. Please try again.', 'danger')
        return redirect(url_for('register'))


@app.route('/verify-email/<token>')
def verify_email(token):
    """Verify user's email with token from email link."""
    user = User.query.filter_by(verification_token=token).first()
    
    if not user:
        log_security_event('VERIFICATION_FAILED', 'invalid_token', ip=request.remote_addr)
        flash('Invalid verification link.', 'danger')
        return redirect(url_for('register'))
    
    # Parse expiry datetime - handle both naive and aware datetimes
    token_expires = user.verification_token_expires
    if token_expires is None:
        log_security_event('VERIFICATION_EXPIRED', f'username={user.username}', user_id=user.id, ip=request.remote_addr)
        flash('Verification link has expired. Please register again.', 'danger')
        return redirect(url_for('register'))
    
    # Convert to timezone-aware if naive (assume IST)
    if token_expires.tzinfo is None:
        token_expires = token_expires.replace(tzinfo=IST)
    
    if token_expires < now_ist():
        log_security_event('VERIFICATION_EXPIRED', f'username={user.username}', user_id=user.id, ip=request.remote_addr)
        flash('Verification link has expired. Please register again.', 'danger')
        return redirect(url_for('register'))
    
    if user.is_verified:
        log_security_event('VERIFICATION_ALREADY_DONE', f'username={user.username}', user_id=user.id, ip=request.remote_addr)
        flash('Email already verified. Please login.', 'info')
        return redirect(url_for('login'))
    
    user.is_verified = True
    user.verification_token = None
    user.verification_token_expires = None
    db.session.commit()
    
    log_security_event('EMAIL_VERIFIED', f'username={user.username}', user_id=user.id, ip=request.remote_addr)
    flash('Email verified successfully! You can now login.', 'success')
    return redirect(url_for('login'))


@app.route('/resend-verification', methods=['POST'])
@limiter.limit("1 per 5 minutes; 5 per hour", error_message="Too many requests. Please wait before resending.")
def resend_verification():
    """Resend verification email for unverified users."""
    email = request.form.get('email', '').strip()
    
    if not email:
        flash('Email is required.', 'danger')
        return redirect(url_for('register', check_email=1))
    
    user = User.query.filter_by(email=email, is_verified=False).first()
    
    if not user:
        # Don't reveal if email exists or not for security
        flash('If this email is registered and unverified, a new verification link has been sent.', 'info')
        return redirect(url_for('register', check_email=1))
    
    token = generate_verification_token()
    user.verification_token = token
    user.verification_token_expires = now_ist() + timedelta(hours=1)
    db.session.commit()
    
    try:
        send_verification_email(user, token)
        log_security_event('VERIFICATION_RESENT', f'username={user.username}', user_id=user.id, ip=request.remote_addr)
        flash('Verification email resent! Please check your inbox (valid for 1 hour).', 'success')
    except Exception as e:
        log_security_event('VERIFICATION_EMAIL_FAILED', f'username={user.username} error={str(e)}', user_id=user.id, ip=request.remote_addr)
        flash('Failed to send verification email. Please try again later.', 'danger')
    
    return redirect(url_for('register', check_email=1))


@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded with proper redirect for form submissions."""
    if request.path == '/resend-verification':
        flash('Too many requests. Please wait 5 minutes before resending.', 'warning')
        return redirect(url_for('register', check_email=1))
    # Default handler for other routes
    retry_after = getattr(e, 'retry_after', 60)
    if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        resp = jsonify({"success": False, "error": "Rate limit exceeded. Please try again later."})
        resp.headers['Retry-After'] = str(retry_after)
        return resp, 429
    return render_template('errors/429.html', retry_after=retry_after), 429


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute; 50 per hour")
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    email = request.form.get('email', '').strip()
    
    if not username or not password or not email:
        log_security_event('LOGIN_FAILURE', 'missing_fields', ip=request.remote_addr)
        flash('All fields are required.', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.filter_by(username=username, email=email).first()
    
    if user and not user.is_verified:
        log_security_event('LOGIN_FAILURE', 'unverified_email', ip=request.remote_addr)
        flash('Please verify your email first. Check your inbox for the verification link.', 'warning')
        return redirect(url_for('login'))
    
    if user and check_password_hash(user.password, password):
        session.clear()  # Prevent session fixation
        session['user_id'] = user.id
        session.permanent = True
        log_security_event('LOGIN_SUCCESS', f'username={username}', user_id=user.id, ip=request.remote_addr)
        flash('Successful login!', 'success')
        return redirect(url_for('dashboard'))
    
    log_security_event('LOGIN_FAILURE', 'invalid_credentials', ip=request.remote_addr)
    flash('Invalid credentials', 'danger')
    return redirect(url_for('login'))

@app.route("/dashboard")
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('home'))
    
    raw_history = (
        CalculationHistory.query
        .filter_by(user_id=session['user_id'])
        .order_by(CalculationHistory.timestamp.desc())
        .limit(10)
        .all()
    )

    processed_history = []
    for entry in raw_history:
        processed_history.append({
            'calc_type': entry.calc_type.replace('_', ' '),
            'params': format_json_data(entry.params),
            'result': format_json_data(entry.result),
            'timestamp': entry.timestamp
        })

    return render_template("index.html", history=processed_history)

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    session.clear()
    log_security_event('LOGOUT', '', user_id=user_id, ip=request.remote_addr)
    flash('Logout successfully!', 'success')
    return redirect(url_for('home'))

@app.route("/calculate", methods=["POST"])
@csrf.exempt  # API endpoint - CSRF handled via custom header
@limiter.limit("30 per minute; 100 per hour")
def calculate():
    # Verify authentication
    if 'user_id' not in session:
        return jsonify({"success": False, "error": "Authentication required"}), 401
    
    # Validate JSON
    if not request.is_json:
        return jsonify({"success": False, "error": "Content-Type must be application/json"}), 400
    
    data = request.get_json()
    if data is None:
        return jsonify({"success": False, "error": "Invalid JSON"}), 400
    
    calc_type = data.get("type")
    params = data.get("params", {})
    
    if not calc_type:
        return jsonify({"success": False, "error": "Missing calculator type"}), 400
    
    # Validate calculator type
    valid_types = [
        "SIP", "LUMPSUM", "SWP", "STEP_UP_SIP", "PPF", "EPF", "NSC",
        "FD_SIMPLE", "RD", "NPS", "RETIREMENT_CALCULATOR", "GRATUITY",
        "SALARY_CALCULATOR", "EMI", "HOME_LOAN_EMI", "CAR_LOAN_EMI",
        "GOLD_LOAN_EMI", "EDUCATION_LOAN_EMI", "FLAT_VS_REDUCING",
        "SIMPLE_INTEREST", "COMPOUND_INTEREST", "GST", "CAGR",
        "INFLATION", "BROKERAGE_CALCULATOR"
    ]
    
    if calc_type not in valid_types:
        return jsonify({"success": False, "error": f"Invalid calculator type"}), 400
    
    # Validate input parameters
    valid, error = validate_calculator_input(calc_type, params)
    if not valid:
        return jsonify({"success": False, "error": error}), 400
    
    def safe_float(val, default=0):
        try:
            return float(val)
        except (ValueError, TypeError):
            return default

    def safe_int(val, default=0):
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    try:
        calculators = {
            "SIP": lambda p: SIP(safe_float(p.get("Monthly investment")), safe_float(p.get("Expected return")), safe_float(p.get("Years")), p.get("Mode", "End of Month")),
            "LUMPSUM": lambda p: LUMPSUM(safe_float(p.get("Total investment")), safe_float(p.get("Expected return")), safe_float(p.get("Years"))),
            "SWP": lambda p: SWP(safe_float(p.get("Total investment")), safe_float(p.get("Withdrawal amount")), safe_float(p.get("Expected rate")), safe_float(p.get("Years"))),
            "STEP_UP_SIP": lambda p: STEP_UP_SIP(safe_float(p.get("Monthly investment")), safe_float(p.get("Step up rate")), safe_float(p.get("Expected return")), safe_float(p.get("Years"))),
            "PPF": lambda p: PPF(safe_float(p.get("Yearly investment")), safe_float(p.get("Annual interest rate")), safe_float(p.get("Years"))),
            "EPF": lambda p: EPF(safe_float(p.get("Basic salary")), safe_float(p.get("DA")), safe_int(p.get("Years of service")), safe_float(p.get("Annual salary growth")), safe_float(p.get("Epf interest rate"))),
            "NSC": lambda p: NSC(safe_float(p.get("Amount invested")), safe_float(p.get("Interest rate")), safe_int(p.get("Years", 5))),
            "FD_SIMPLE": lambda p: FD_SIMPLE(safe_float(p.get("Principal")), safe_float(p.get("Interest rate")), safe_float(p.get("Years"))),
            "RD": lambda p: RD(safe_float(p.get("Monthly investment")), safe_float(p.get("Expected rate")), safe_float(p.get("Years"))),
            "NPS": lambda p: NPS(safe_float(p.get("Monthly investment")), safe_float(p.get("Annual return")), safe_int(p.get("Current age")), safe_int(p.get("Retirement age", 60))),
            "RETIREMENT_CALCULATOR": lambda p: RETIREMENT_CALCULATOR(safe_int(p.get("Age")), safe_float(p.get("Monthly expense")), safe_int(p.get("Retirement age", 60)), safe_int(p.get("Life expectancy", 85)), safe_float(p.get("Inflation", 6)), safe_float(p.get("Annual return", 7))),
            "GRATUITY": lambda p: GRATUITY(safe_float(p.get("Basic salary")), safe_float(p.get("DA")), safe_float(p.get("Years of service"))),
            "SALARY_CALCULATOR": lambda p: SALARY_CALCULATOR(safe_float(p.get("CTC")), safe_float(p.get("Bonus")), safe_float(p.get("Professional tax")), safe_float(p.get("Employer pf")), safe_float(p.get("Employee pf")), safe_float(p.get("Other deductions"))),
            "EMI": lambda p: EMI(safe_float(p.get("Loan amount")), safe_float(p.get("Interest rate")), safe_float(p.get("Years"))),
            "HOME_LOAN_EMI": lambda p: HOME_LOAN_EMI(safe_float(p.get("Loan amount")), safe_float(p.get("Interest rate")), safe_float(p.get("Years"))),
            "CAR_LOAN_EMI": lambda p: CAR_LOAN_EMI(safe_float(p.get("Loan amount")), safe_float(p.get("Interest rate")), safe_float(p.get("Years"))),
            "GOLD_LOAN_EMI": lambda p: GOLD_LOAN_EMI(safe_float(p.get("Loan amount")), safe_float(p.get("Interest rate")), safe_float(p.get("Years"))),
            "EDUCATION_LOAN_EMI": lambda p: EDUCATION_LOAN_EMI(safe_float(p.get("Loan amount")), safe_float(p.get("Interest rate")), safe_float(p.get("Years"))),
            "FLAT_VS_REDUCING": lambda p: FLAT_VS_REDUCING(safe_float(p.get("Principal")), safe_float(p.get("Annual rate")), safe_float(p.get("Years"))),
            "SIMPLE_INTEREST": lambda p: SIMPLE_INTEREST(safe_float(p.get("Principal amount")), safe_float(p.get("Rate of interest")), safe_float(p.get("Years"))),
            "COMPOUND_INTEREST": lambda p: COMPOUND_INTEREST(safe_float(p.get("Principal amount")), safe_float(p.get("Interest rate")), safe_float(p.get("Years")), safe_int(p.get("Compounding_per_year", 4))),
            "GST": lambda p: GST(safe_float(p.get("Original price")), safe_float(p.get("Gst rate"))),
            "CAGR": lambda p: CAGR(safe_float(p.get("Initial value")), safe_float(p.get("Final value")), safe_float(p.get("Years"))),
            "INFLATION": lambda p: INFLATION(safe_float(p.get("Current price")), safe_float(p.get("Rate")), safe_float(p.get("Years"))),
            "BROKERAGE_CALCULATOR": lambda p: BROKERAGE_CALCULATOR(p.get("Segment", "delivery"), safe_int(p.get("Quantity")), safe_float(p.get("Buy price")), safe_float(p.get("Sell price")), safe_float(p.get("Brokerage")))
        }

        if calc_type in calculators:
            result = calculators[calc_type](params)
            
            # Format params for storage/display in Indian number system
            formatted_params = {}
            for key, value in params.items():
                decimals = PARAM_DECIMALS.get(key, 2)
                try:
                    formatted_params[key] = format_indian_raw(float(value), decimals)
                except (ValueError, TypeError):
                    formatted_params[key] = value
            
            # Store Result in History (only for authenticated users)
            if 'user_id' in session:
                history_entry = CalculationHistory(
                    user_id=session['user_id'],
                    calc_type=calc_type,
                    params=json.dumps(formatted_params),
                    result=json.dumps(result)
                )
                db.session.add(history_entry)
                db.session.commit()

            return jsonify({"success": True, "result": result, "formatted_params": formatted_params})
        else:
            return jsonify({"success": False, "error": f"Unknown calculator type: {calc_type}"}), 400

    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        log_security_event('CALCULATION_ERROR', f'type={calc_type} error={str(e)}', user_id=session.get('user_id'), ip=request.remote_addr)
        return jsonify({"success": False, "error": "Calculation failed"}), 500

if __name__ == "__main__":
    debug_mode = os.environ.get('FLASK_DEBUG', 'true').lower() == 'true'
    app.run(debug=debug_mode)