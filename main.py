from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response, session, flash, abort
import sqlite3
from datetime import datetime, timedelta
import csv
import io
import re
import uuid
from functools import wraps
import time
import os
import secrets
from urllib.parse import urljoin, urlparse
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from openpyxl import Workbook
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
IS_PRODUCTION = os.environ.get('FLASK_ENV', '').lower() == 'production'
secret_key = os.environ.get('SECRET_KEY')
if IS_PRODUCTION and not secret_key:
    raise RuntimeError('SECRET_KEY is required when FLASK_ENV=production')
app.secret_key = secret_key or secrets.token_hex(32)
app.permanent_session_lifetime = timedelta(minutes=5)  # Session expires in 5 minutes

# Enhanced security configuration
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,    # Prevent JavaScript access
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=5)  # 5-minute timeout
)

# Initialize rate limiter for brute force protection
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["1000 per hour"],  # General rate limit
    storage_uri="memory://"  # Use Redis in production
)

# Brute force protection tracking
failed_attempts = {}  # Track failed attempts per IP
account_lockouts = {}  # Track account lockouts

# Active sessions tracking (in production, use Redis or database)
ACTIVE_SESSIONS = {}

# Track password change attempts to prevent loops
PASSWORD_CHANGE_ATTEMPTS = {}

# Password requirements based on industry standards (NIST/OWASP)
PASSWORD_REQUIREMENTS = {
    'superadmin': {
        'min_length': 14,
        'require_uppercase': True,
        'require_lowercase': True,
        'require_numbers': True,
        'require_special': True,
        'description': 'Minimum 14 characters with uppercase, lowercase, numbers, and special characters'
    },
    'admin': {
        'min_length': 12,
        'require_uppercase': True,
        'require_lowercase': True, 
        'require_numbers': True,
        'require_special': False,  # Admin convenience
        'description': 'Minimum 12 characters with uppercase, lowercase, and numbers'
    },
    'editor': {
        'min_length': 12,
        'require_uppercase': True,
        'require_lowercase': True,
        'require_numbers': True, 
        'require_special': True,
        'description': 'Minimum 12 characters with uppercase, lowercase, numbers, and special characters'
    },
    'viewer': {
        'min_length': 12,
        'require_uppercase': True,
        'require_lowercase': True,
        'require_numbers': True,
        'require_special': True,
        'description': 'Minimum 12 characters with uppercase, lowercase, numbers, and special characters'
    }
}

# Initial local credential. Production deployments must set INITIAL_ADMIN_PASSWORD.
DEFAULT_ADMIN = {
    'username': 'admin',
    'password': os.environ.get('INITIAL_ADMIN_PASSWORD', 'ChangeMeNow2026!')
}

DATABASE_PATH = os.environ.get('DATABASE_PATH', 'audit_findings.db')

if IS_PRODUCTION and not os.environ.get('INITIAL_ADMIN_PASSWORD') and not os.path.exists(DATABASE_PATH):
    raise RuntimeError('INITIAL_ADMIN_PASSWORD is required for first-time production setup')

def get_csrf_token():
    """Return a stable, cryptographically random token for the current session."""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_urlsafe(32)
    return session['_csrf_token']

@app.before_request
def validate_csrf_token():
    if request.method in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        submitted = request.form.get('_csrf_token') or request.headers.get('X-CSRF-Token')
        expected = session.get('_csrf_token')
        if not expected or not submitted or not secrets.compare_digest(expected, submitted):
            abort(400, description='Invalid or missing CSRF token')

@app.errorhandler(400)
def handle_bad_request(error):
    if getattr(error, 'description', '') != 'Invalid or missing CSRF token':
        return error

    session.clear()
    flash('Your session expired after an application update. Please sign in again.', 'warning')
    return redirect(url_for('login'))

@app.context_processor
def inject_csrf_token():
    return {'csrf_token': get_csrf_token}

def is_safe_redirect_target(target):
    if not target:
        return False
    host_url = urlparse(request.host_url)
    redirect_url = urlparse(urljoin(request.host_url, target))
    return redirect_url.scheme in {'http', 'https'} and host_url.netloc == redirect_url.netloc

# Brute force protection functions
def get_delay_for_ip(ip_address):
    """Calculate progressive delay based on failed attempts"""
    attempts = failed_attempts.get(ip_address, 0)
    if attempts == 0:
        return 0
    elif attempts < 3:
        return 1  # 1 second delay
    elif attempts < 5:
        return 2  # 2 second delay  
    elif attempts < 8:
        return 5  # 5 second delay
    else:
        return 10  # 10 second delay

def record_failed_attempt(ip_address, username):
    """Record failed login attempt with progressive delays"""
    failed_attempts[ip_address] = failed_attempts.get(ip_address, 0) + 1
    log_activity('LOGIN_FAILED', f'Failed login attempt #{failed_attempts[ip_address]} from {ip_address}', username)
    
def reset_failed_attempts(ip_address):
    """Reset counter on successful login"""
    if ip_address in failed_attempts:
        del failed_attempts[ip_address]

def is_account_locked(username):
    """Check if account is temporarily locked due to failed attempts"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check recent failed attempts (last 15 minutes)
    cursor.execute("""
        SELECT COUNT(*) FROM activity_logs 
        WHERE username = ? AND action = 'LOGIN_FAILED' 
        AND timestamp > datetime('now', '-15 minutes')
    """, (username,))
    
    result = cursor.fetchone()
    failed_count = result[0] if result else 0
    conn.close()
    
    return failed_count >= 5  # Lock after 5 failed attempts in 15 minutes

@app.after_request
def set_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    # Only add HSTS in production with HTTPS
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # Updated CSP to allow Heroicons and other external resources
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://fonts.googleapis.com; font-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; img-src 'self' data: https: blob:; connect-src 'self' https:;"
    return response

# Database setup
def init_db():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        audit_reference TEXT,
        audit_report TEXT,
        observations TEXT,
        observation_details TEXT,
        report_date TEXT,
        priority TEXT,
        recommendation TEXT,
        management_response TEXT,
        target_date TEXT,
        revised_target_date TEXT,
        completion_date TEXT,
        person_responsible TEXT,
        department TEXT,
        status TEXT,
        validated TEXT,
        testing_procedures TEXT,
        comments TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT
    )
    """)
    
    # Create activity logs table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        user_agent TEXT,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
        session_id TEXT
    )
    """)
    
    # Migrate the original role constraint and promote existing administrators.
    users_sql = cursor.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'"
    ).fetchone()
    if users_sql and "'superadmin'" not in users_sql[0]:
        cursor.execute("""
        CREATE TABLE users_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'viewer' CHECK (role IN ('superadmin', 'admin', 'editor', 'viewer')),
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT,
            is_active BOOLEAN DEFAULT 1,
            must_change_password BOOLEAN DEFAULT 0,
            temp_password BOOLEAN DEFAULT 0,
            created_by TEXT
        )
        """)
        cursor.execute("""
        INSERT INTO users_new
        SELECT id, username, password, CASE WHEN role = 'admin' THEN 'superadmin' ELSE role END,
               created_at, updated_at, is_active, must_change_password, temp_password, created_by
        FROM users
        """)
        cursor.execute('DROP TABLE users')
        cursor.execute('ALTER TABLE users_new RENAME TO users')

    # Create users table for password management
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'viewer' CHECK (role IN ('superadmin', 'admin', 'editor', 'viewer')),
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT,
        is_active BOOLEAN DEFAULT 1,
        must_change_password BOOLEAN DEFAULT 0,
        temp_password BOOLEAN DEFAULT 0,
        created_by TEXT
    )
    """)
    
    # Insert default admin user if not exists
    cursor.execute("""
    INSERT OR IGNORE INTO users (username, password, role, must_change_password, temp_password)
    VALUES (?, ?, ?, 1, 1)
    """, (DEFAULT_ADMIN['username'], generate_password_hash(DEFAULT_ADMIN['password']), 'superadmin'))

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        recipient TEXT NOT NULL,
        sender TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        read_at TEXT
    )
    """)
    
    conn.commit()
    conn.close()

# WSGI servers import the module without running the __main__ block.
init_db()

def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Activity logging functions
def log_activity(action, details=None, username_override=None):
    """Log user activity to the database"""
    try:
        conn = get_db_connection()
        username = username_override or session.get('username', 'Anonymous')
        session_id = session.get('session_id', 'N/A')
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', 'Unknown')
        timestamp = datetime.now().isoformat()
        
        conn.execute("""
            INSERT INTO activity_logs (username, action, details, ip_address, user_agent, timestamp, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (username, action, details, ip_address, user_agent, timestamp, session_id))
        
        conn.commit()
        conn.close()
        print(f"📝 Activity logged: {username} - {action}")
    except Exception as e:
        print(f"❌ Failed to log activity: {e}")

def get_user_from_db(username):
    """Get user from database"""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    
    if user:
        # Convert sqlite3.Row to dictionary for easier access
        return dict(user)
    return None

def update_user_password(username, new_password):
    """Update user password in database"""
    conn = get_db_connection()
    conn.execute("""
        UPDATE users SET password = ?, updated_at = ?, must_change_password = 0, temp_password = 0 WHERE username = ?
    """, (generate_password_hash(new_password), datetime.now().isoformat(), username))
    conn.commit()
    conn.close()

def create_user(username, temp_password, role, created_by):
    """Create a new user with temporary password"""
    try:
        conn = get_db_connection()
        conn.execute("""
            INSERT INTO users (username, password, role, created_by, must_change_password, temp_password, created_at)
            VALUES (?, ?, ?, ?, 1, 1, ?)
        """, (username, generate_password_hash(temp_password), role, created_by, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False  # Username already exists

def get_all_users():
    """Get all users for admin management"""
    conn = get_db_connection()
    users = conn.execute("""
        SELECT id, username, role, is_active, must_change_password, temp_password, created_at, created_by
        FROM users ORDER BY created_at DESC
    """).fetchall()
    conn.close()
    
    # Convert sqlite3.Row objects to dictionaries
    return [dict(user) for user in users]

def validate_password_requirements(password, role):
    """Validate password based on industry standards (NIST/OWASP)"""
    requirements = PASSWORD_REQUIREMENTS.get(role, PASSWORD_REQUIREMENTS['viewer'])
    errors = []
    
    # Check minimum length
    if len(password) < requirements['min_length']:
        errors.append(f"Password must be at least {requirements['min_length']} characters long")
    
    # Check for uppercase letters
    if requirements['require_uppercase'] and not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter")
    
    # Check for lowercase letters  
    if requirements['require_lowercase'] and not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter")
    
    # Check for numbers
    if requirements['require_numbers'] and not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one number")
    
    # Check for special characters
    if requirements['require_special']:
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if not any(c in special_chars for c in password):
            errors.append("Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)")
    
    # Check for common weak patterns
    weak_patterns = ['123', 'abc', 'password', 'admin', 'user', '000', '111', '999']
    password_lower = password.lower()
    for pattern in weak_patterns:
        if pattern in password_lower:
            errors.append(f"Password should not contain common patterns like '{pattern}'")
            break
    
    if errors:
        return False, " | ".join(errors)
    return True, requirements['description']

def deactivate_user(username):
    """Deactivate a user account"""
    conn = get_db_connection()
    conn.execute("""
        UPDATE users SET is_active = 0, updated_at = ? WHERE username = ?
    """, (datetime.now().isoformat(), username))
    conn.commit()
    conn.close()

def activate_user(username):
    """Activate a user account"""
    conn = get_db_connection()
    conn.execute("""
        UPDATE users SET is_active = 1, updated_at = ? WHERE username = ?
    """, (datetime.now().isoformat(), username))
    conn.commit()
    conn.close()

def is_admin(username):
    """Check if user is admin"""
    user = get_user_from_db(username)
    return user and user['role'] in {'superadmin', 'admin'}

def is_superadmin(username):
    user = get_user_from_db(username)
    return user and user['role'] == 'superadmin'

def verify_password(user, candidate):
    """Verify a password and transparently migrate legacy plaintext values."""
    stored = user['password']
    if stored.startswith(('scrypt:', 'pbkdf2:')):
        return check_password_hash(stored, candidate)
    if secrets.compare_digest(stored, candidate):
        conn = get_db_connection()
        conn.execute('UPDATE users SET password = ?, updated_at = ? WHERE username = ?',
                     (generate_password_hash(candidate), datetime.now().isoformat(), user['username']))
        conn.commit()
        conn.close()
        return True
    return False

# Session management functions
def generate_session_id():
    """Generate a unique session ID"""
    return str(uuid.uuid4())

def invalidate_previous_sessions(username):
    """Invalidate all previous sessions for a user"""
    global ACTIVE_SESSIONS
    sessions_to_remove = []
    for session_id, session_data in ACTIVE_SESSIONS.items():
        if session_data.get('username') == username:
            sessions_to_remove.append(session_id)
    
    for session_id in sessions_to_remove:
        del ACTIVE_SESSIONS[session_id]
        print(f"🚫 Invalidated previous session: {session_id[:8]}...")

def is_session_valid(username, session_id):
    """Check if the current session is the active one for the user"""
    return (session_id in ACTIVE_SESSIONS and 
            ACTIVE_SESSIONS[session_id].get('username') == username)

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or 'session_id' not in session:
            # Special handling for force password change to prevent loops
            if request.endpoint == 'force_password_change':
                session.clear()
                flash('Session expired. Please log in again.', 'error')
                return redirect(url_for('login'))
            return redirect(url_for('login', next=request.url))
        
        username = session.get('username')
        session_id = session.get('session_id')
        
        # Check for session timeout
        if check_session_timeout():
            print(f"⏰ Session timed out for user: {username}")
            session.clear()
            # Special handling for force password change to prevent loops
            if request.endpoint == 'force_password_change':
                flash('Session expired during password change. Please log in again.', 'error')
                return redirect(url_for('login'))
            flash('Your session has expired due to inactivity. Please log in again.', 'warning')
            return redirect(url_for('login', next=request.url))
        
        # Check if this is the active session for the user
        if not is_session_valid(username, session_id):
            print(f"⚠️ Session terminated for user: {username} (login from another location)")
            session.clear()
            # Special handling for force password change to prevent loops
            if request.endpoint == 'force_password_change':
                flash('Session terminated. Please log in again.', 'error')
                return redirect(url_for('login'))
            flash('Your session has been terminated due to login from another location.', 'info')
            return redirect(url_for('login', next=request.url))
        
        # Update last activity timestamp
        update_session_activity()
        
        # CRITICAL SECURITY: Check if user must change password and restrict access
        user = get_user_from_db(username)
        if not user or not user['is_active']:
            session.clear()
            return redirect(url_for('login'))
        session['user_role'] = user['role']
        if user and user['must_change_password']:
            # Only allow access to force_password_change, logout, and reset_password_loop
            allowed_endpoints = {'force_password_change', 'logout', 'reset_password_loop'}
            
            if request.endpoint not in allowed_endpoints:
                print(f"🔒 Access denied for user {username} - must change password first (attempted: {request.endpoint})")
                log_activity('UNAUTHORIZED_ACCESS_ATTEMPT', f'User tried to access {request.endpoint} without changing mandatory password')
                flash('You must change your password before accessing other parts of the system.', 'warning')
                return redirect(url_for('force_password_change'))
        
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        username = session.get('username')
        if not is_admin(username):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def roles_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            user = get_user_from_db(session.get('username'))
            if not user or user['role'] not in allowed_roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def superadmin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not is_superadmin(session.get('username')):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def check_session_timeout():
    """Check if session has timed out"""
    if 'last_activity' in session:
        last_activity = datetime.fromisoformat(session['last_activity'])
        if datetime.now() - last_activity > timedelta(minutes=5):
            return True
    return False

def update_session_activity():
    """Update last activity timestamp"""
    session['last_activity'] = datetime.now().isoformat()

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")  # Rate limiting: max 10 attempts per minute
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = request.form.get('remember')
        client_ip = request.remote_addr
        
        # Check for account lockout
        if is_account_locked(username):
            log_activity('LOGIN_BLOCKED', f'Login blocked for locked account {username} from {client_ip}', username)
            flash('Account temporarily locked due to multiple failed attempts. Please try again later.', 'error')
            return render_template('login.html', error='Account temporarily locked', current_year=datetime.now().year)
        
        # Apply progressive delay for repeated failed attempts from same IP
        delay = get_delay_for_ip(client_ip)
        if delay > 0:
            print(f"⏱️ Applying {delay}s delay for IP {client_ip} (attempt #{failed_attempts.get(client_ip, 0)})")
            time.sleep(delay)
        
        # Get user from database
        user = get_user_from_db(username)
        
        # Simple authentication (in production, use proper password hashing)
        if user and user['is_active'] and verify_password(user, password):
            # Successful login - reset failed attempts for this IP
            reset_failed_attempts(client_ip)
            
            # Invalidate any previous sessions for this user
            invalidate_previous_sessions(username)
            
            # Generate new session ID
            new_session_id = generate_session_id()
            
            # Store session data
            session['logged_in'] = True
            session['username'] = username
            session['session_id'] = new_session_id
            session['user_role'] = user['role']
            update_session_activity()  # Set initial activity timestamp
            
            # Track active session globally
            ACTIVE_SESSIONS[new_session_id] = {
                'username': username,
                'login_time': datetime.now().isoformat(),
                'user_agent': request.headers.get('User-Agent', 'Unknown'),
                'ip_address': request.remote_addr
            }
            
            # Make session permanent if "Remember me" is checked
            if remember:
                session.permanent = True
            else:
                session.permanent = False
            
            # Log successful login
            log_activity('LOGIN', f'Successful login from {request.remote_addr}')
            
            print(f"✅ User '{username}' logged in successfully (Session: {new_session_id[:8]}...)")
            
            # Check if user must change password (temporary password)
            if user['must_change_password']:
                # Extra safety check: ensure password change is actually required
                fresh_user_check = get_user_from_db(username)
                if fresh_user_check and fresh_user_check['must_change_password']:
                    flash('You must change your temporary password before continuing.', 'warning')
                    return redirect(url_for('force_password_change'))
                else:
                    # Flag was cleared, proceed normally
                    print(f"🔄 Password change flag cleared for user {username} during login")
            
            flash('Login successful!', 'success')
            
            # Redirect to next page or index
            next_page = request.args.get('next')
            # Prevent redirect loops to force-password-change
            if next_page and 'force-password-change' in next_page:
                next_page = None
            redirect_url = next_page if is_safe_redirect_target(next_page) else url_for('index')
            return redirect(redirect_url)
        else:
            # Record failed attempt
            record_failed_attempt(client_ip, username)
            
            # Enhanced logging for failed attempts
            attempt_count = failed_attempts.get(client_ip, 0)
            try:
                conn = get_db_connection()
                conn.execute("""
                    INSERT INTO activity_logs (username, action, details, ip_address, user_agent, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (username, 'LOGIN_FAILED', 
                      f'Failed login attempt #{attempt_count} from {client_ip}', 
                      client_ip, request.headers.get('User-Agent', 'Unknown'), 
                      datetime.now().isoformat()))
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"⚠️ Error logging failed attempt: {e}")
            
            # Show appropriate error message
            if attempt_count >= 3:
                flash(f'Invalid credentials. Too many failed attempts (#{attempt_count}). Further attempts will be delayed.', 'error')
            else:
                flash('Invalid username or password', 'error')
            
            return render_template('login.html', error='Invalid username or password', current_year=datetime.now().year)
    
    return render_template('login.html', current_year=datetime.now().year)

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    # Log logout activity before clearing session
    log_activity('LOGOUT', 'User logged out')
    
    # Clean up session tracking
    session_id = session.get('session_id')
    username = session.get('username')
    
    if session_id and session_id in ACTIVE_SESSIONS:
        del ACTIVE_SESSIONS[session_id]
        print(f"🚫 Removed session {session_id[:8]}... for user: {username}")
    
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/admin/sessions')
@admin_required
def view_sessions():
    """Admin route to view active sessions (for debugging)"""
    log_activity('VIEW_SESSIONS', 'Accessed active sessions page')
    return jsonify({
        'active_sessions': len(ACTIVE_SESSIONS),
        'sessions': {
            sid[:8] + '...': {
                'username': data['username'],
                'login_time': data['login_time'],
                'ip_address': data.get('ip_address', 'Unknown')
            }
            for sid, data in ACTIVE_SESSIONS.items()
        }
    })

@app.route('/activity-logs')
@roles_required('superadmin', 'admin', 'editor')
def activity_logs():
    """View activity logs"""
    log_activity('VIEW_ACTIVITY_LOGS', 'Accessed activity logs page')
    
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = 50  # Show 50 logs per page
    offset = (page - 1) * per_page
    
    conn = get_db_connection()
    
    # Get total count for pagination
    total_count = conn.execute('SELECT COUNT(*) FROM activity_logs').fetchone()[0]
    
    # Get logs for current page
    logs = conn.execute('''
        SELECT * FROM activity_logs 
        ORDER BY timestamp DESC 
        LIMIT ? OFFSET ?
    ''', (per_page, offset)).fetchall()
    
    conn.close()
    
    # Calculate pagination info
    total_pages = (total_count + per_page - 1) // per_page
    has_prev = page > 1
    has_next = page < total_pages
    
    return render_template('activity_logs.html', 
                         logs=logs, 
                         page=page, 
                         total_pages=total_pages,
                         has_prev=has_prev,
                         has_next=has_next,
                         total_count=total_count)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """User settings page"""
    username = session.get('username')
    user = get_user_from_db(username)
    
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate inputs
        if not current_password or not new_password or not confirm_password:
            flash('All password fields are required', 'error')
            return render_template('settings.html', user=user, password_requirements=PASSWORD_REQUIREMENTS)
        
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return render_template('settings.html', user=user, password_requirements=PASSWORD_REQUIREMENTS)
        
        # Validate password requirements based on role
        is_valid, message = validate_password_requirements(new_password, user['role'])
        if not is_valid:
            flash(message, 'error')
            return render_template('settings.html', user=user, password_requirements=PASSWORD_REQUIREMENTS)
        
        # Verify current password
        if not user or not verify_password(user, current_password):
            flash('Current password is incorrect', 'error')
            log_activity('PASSWORD_CHANGE_FAILED', 'Incorrect current password provided')
            return render_template('settings.html', user=user, password_requirements=PASSWORD_REQUIREMENTS)
        
        # Update password
        update_user_password(username, new_password)
        log_activity('PASSWORD_CHANGED', 'Password successfully changed')
        flash('Password changed successfully!', 'success')
        
        return redirect(url_for('settings'))
    
    log_activity('VIEW_SETTINGS', 'Accessed settings page')
    return render_template('settings.html', user=user, password_requirements=PASSWORD_REQUIREMENTS)

@app.route('/force-password-change', methods=['GET', 'POST'])
@limiter.limit("20 per minute")  # Rate limiting for password changes
@login_required
def force_password_change():
    """Force password change for users with temporary passwords"""
    username = session.get('username')
    session_id = session.get('session_id')
    
    # Loop detection: track attempts per session
    if session_id not in PASSWORD_CHANGE_ATTEMPTS:
        PASSWORD_CHANGE_ATTEMPTS[session_id] = {'count': 0, 'timestamp': datetime.now()}
    
    # Check for excessive attempts (potential loop)
    attempts = PASSWORD_CHANGE_ATTEMPTS[session_id]
    if attempts['count'] > 10:  # More than 10 attempts indicates a problem
        time_diff = datetime.now() - attempts['timestamp']
        if time_diff.total_seconds() < 300:  # Within 5 minutes
            print(f"🚨 Potential password change loop detected for user {username} (session: {session_id[:8]}...)")
            log_activity('PASSWORD_CHANGE_LOOP_DETECTED', f'Excessive password change attempts: {attempts["count"]}')
            session.clear()
            if session_id in PASSWORD_CHANGE_ATTEMPTS:
                del PASSWORD_CHANGE_ATTEMPTS[session_id]
            flash('Too many password change attempts detected. Please contact your administrator for assistance.', 'error')
            return redirect(url_for('login'))
    
    # Increment attempt counter
    PASSWORD_CHANGE_ATTEMPTS[session_id]['count'] += 1
    
    user = get_user_from_db(username)
    
    # Safety check: If user doesn't exist or is inactive, clear session and redirect to login
    if not user or not user['is_active']:
        session.clear()
        if session_id in PASSWORD_CHANGE_ATTEMPTS:
            del PASSWORD_CHANGE_ATTEMPTS[session_id]
        flash('Account not found or inactive. Please contact administrator.', 'error')
        return redirect(url_for('login'))
    
    # If user doesn't need to change password, redirect to dashboard and clean up
    if not user['must_change_password']:
        if session_id in PASSWORD_CHANGE_ATTEMPTS:
            del PASSWORD_CHANGE_ATTEMPTS[session_id]
        flash('Password change not required. Redirecting to dashboard.', 'info')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate inputs
        if not current_password or not new_password or not confirm_password:
            flash('All password fields are required', 'error')
            return render_template('force_password_change.html', user=user, password_requirements=PASSWORD_REQUIREMENTS)
        
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return render_template('force_password_change.html', user=user, password_requirements=PASSWORD_REQUIREMENTS)
        
        # Validate password requirements based on role
        is_valid, message = validate_password_requirements(new_password, user['role'])
        if not is_valid:
            flash(message, 'error')
            return render_template('force_password_change.html', user=user, password_requirements=PASSWORD_REQUIREMENTS)
        
        # CRITICAL SECURITY: Prevent reuse of temporary password
        if new_password == current_password:
            flash('New password cannot be the same as your current temporary password. You must choose a different password.', 'error')
            log_activity('PASSWORD_CHANGE_FAILED', 'Attempted to reuse temporary password as new password')
            return render_template('force_password_change.html', user=user, password_requirements=PASSWORD_REQUIREMENTS)
        
        # Verify current password (temporary password)
        if not verify_password(user, current_password):
            flash('Current temporary password is incorrect', 'error')
            log_activity('PASSWORD_CHANGE_FAILED', 'Incorrect temporary password provided')
            return render_template('force_password_change.html', user=user, password_requirements=PASSWORD_REQUIREMENTS)
        
        # Update password and remove temporary flag
        try:
            update_user_password(username, new_password)
            log_activity('PASSWORD_CHANGED', 'Temporary password successfully changed')
            
            # Double-check that the flags were properly updated
            updated_user = get_user_from_db(username)
            if updated_user and not updated_user['must_change_password']:
                # Clean up tracking
                if session_id in PASSWORD_CHANGE_ATTEMPTS:
                    del PASSWORD_CHANGE_ATTEMPTS[session_id]
                print(f"✅ Password successfully changed for user {username}, flags cleared")
                flash('Password changed successfully! You can now use the system normally.', 'success')
                return redirect(url_for('index'))
            else:
                # If there was an issue with updating, log it and try again
                print(f"⚠️ Warning: Password flags not properly updated for user {username}")
                flash('Password updated but there was a system issue. Please try logging in again.', 'warning')
                session.clear()
                if session_id in PASSWORD_CHANGE_ATTEMPTS:
                    del PASSWORD_CHANGE_ATTEMPTS[session_id]
                return redirect(url_for('login'))
                
        except Exception as e:
            print(f"❌ Error updating password for user {username}: {e}")
            flash('An error occurred while updating your password. Please try again.', 'error')
            log_activity('PASSWORD_CHANGE_FAILED', f'System error during password update: {str(e)}')
            return render_template('force_password_change.html', user=user, password_requirements=PASSWORD_REQUIREMENTS)
    
    return render_template('force_password_change.html', user=user, password_requirements=PASSWORD_REQUIREMENTS)

@app.route('/reset-password-loop')
def reset_password_loop():
    """Emergency route to break password change loops"""
    # Clear session and provide clean login
    session.clear()
    flash('Password change session has been reset. Please log in again.', 'info')
    print(f"🔄 Password change loop reset requested from IP: {request.remote_addr}")
    return redirect(url_for('login'))

@app.route('/admin/users')
@superadmin_required
def manage_users():
    """Admin page to manage users"""
    users = get_all_users()
    log_activity('VIEW_USER_MANAGEMENT', 'Accessed user management page')
    return render_template('admin/manage_users.html', users=users, password_requirements=PASSWORD_REQUIREMENTS)

@app.route('/admin/users/add', methods=['GET', 'POST'])
@superadmin_required
def add_user():
    """Admin page to add new user"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        temp_password = request.form.get('temp_password', '').strip()
        role = request.form.get('role', 'viewer')
        
        # Validate inputs
        if not username or not temp_password:
            flash('Username and temporary password are required', 'error')
            return render_template('admin/add_user.html', password_requirements=PASSWORD_REQUIREMENTS)
        
        if role not in ['superadmin', 'admin', 'editor', 'viewer']:
            flash('Invalid role selected', 'error')
            return render_template('admin/add_user.html', password_requirements=PASSWORD_REQUIREMENTS)
        
        # Validate temporary password requirements
        is_valid, message = validate_password_requirements(temp_password, role)
        if not is_valid:
            flash(f"Temporary password error: {message}", 'error')
            return render_template('admin/add_user.html', password_requirements=PASSWORD_REQUIREMENTS)
        
        # Create user
        created_by = session.get('username')
        if create_user(username, temp_password, role, created_by):
            log_activity('CREATE_USER', f'Created new user: {username} with role: {role}')
            flash(f'User "{username}" created successfully with temporary password. They must change it on first login.', 'success')
            return redirect(url_for('manage_users'))
        else:
            flash('Username already exists', 'error')
    
    return render_template('admin/add_user.html', password_requirements=PASSWORD_REQUIREMENTS)

@app.route('/admin/users/<username>/toggle-status', methods=['POST'])
@superadmin_required
def toggle_user_status(username):
    """Toggle user active/inactive status"""
    user = get_user_from_db(username)
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('manage_users'))
    
    # Prevent admin from deactivating themselves
    current_user = session.get('username')
    if username == current_user:
        flash('You cannot deactivate your own account', 'error')
        return redirect(url_for('manage_users'))
    
    if user['is_active']:
        deactivate_user(username)
        log_activity('DEACTIVATE_USER', f'Deactivated user: {username}')
        flash(f'User "{username}" has been deactivated', 'info')
    else:
        activate_user(username)
        log_activity('ACTIVATE_USER', f'Activated user: {username}')
        flash(f'User "{username}" has been activated', 'success')
    
    return redirect(url_for('manage_users'))

@app.route('/admin/users/<username>/delete', methods=['POST'])
@superadmin_required
def delete_user(username):
    if username == session.get('username'):
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('manage_users'))

    user = get_user_from_db(username)
    if not user:
        abort(404)
    if user['role'] == 'superadmin':
        conn = get_db_connection()
        count = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'superadmin'").fetchone()[0]
        conn.close()
        if count <= 1:
            flash('The last superadmin account cannot be deleted.', 'error')
            return redirect(url_for('manage_users'))

    conn = get_db_connection()
    conn.execute('DELETE FROM user_alerts WHERE recipient = ?', (username,))
    conn.execute('DELETE FROM users WHERE username = ?', (username,))
    conn.commit()
    conn.close()
    invalidate_previous_sessions(username)
    log_activity('DELETE_USER', f'Deleted user: {username}')
    flash(f'User "{username}" was deleted.', 'success')
    return redirect(url_for('manage_users'))

@app.route('/admin/users/<username>/alert', methods=['POST'])
@superadmin_required
def send_user_alert(username):
    if not get_user_from_db(username):
        abort(404)
    message = request.form.get('message', '').strip()
    if not message or len(message) > 500:
        flash('Alert text must be between 1 and 500 characters.', 'error')
        return redirect(url_for('manage_users'))

    conn = get_db_connection()
    conn.execute(
        'INSERT INTO user_alerts (recipient, sender, message) VALUES (?, ?, ?)',
        (username, session['username'], message),
    )
    conn.commit()
    conn.close()
    log_activity('SEND_USER_ALERT', f'Sent alert to {username}')
    flash(f'Alert sent to "{username}".', 'success')
    return redirect(url_for('manage_users'))

@app.route('/alerts/<int:alert_id>/read', methods=['POST'])
@login_required
def mark_alert_read(alert_id):
    conn = get_db_connection()
    conn.execute(
        'UPDATE user_alerts SET read_at = ? WHERE id = ? AND recipient = ?',
        (datetime.now().isoformat(), alert_id, session['username']),
    )
    conn.commit()
    conn.close()
    return redirect(request.referrer if is_safe_redirect_target(request.referrer) else url_for('index'))

@app.route('/')
@login_required
def index():
    log_activity('VIEW_DASHBOARD', 'Accessed main dashboard')
    conn = get_db_connection()
    findings = conn.execute('''
        SELECT id, audit_reference, audit_report, status, priority, 
               target_date, person_responsible, created_at 
        FROM audit_findings 
        ORDER BY created_at DESC
    ''').fetchall()
    conn.close()
    return render_template('index.html', findings=findings)

@app.route('/findings')
@login_required
def findings():
    conn = get_db_connection()
    findings = conn.execute('''
        SELECT id, audit_reference, audit_report, status, priority, 
               target_date, person_responsible 
        FROM audit_findings 
        ORDER BY created_at DESC
    ''').fetchall()
    conn.close()
    return render_template('findings.html', findings=findings)

@app.route('/add', methods=['GET', 'POST'])
@roles_required('superadmin', 'admin', 'editor')
def add_finding():
    if request.method == 'POST':
        conn = get_db_connection()
        now = datetime.now().isoformat()
        
        # Handle conditional audit report field
        audit_reference = request.form.get('audit_reference', '').strip()
        if audit_reference in ['24-07', '25-05']:
            audit_report = request.form.get('audit_report_custom', '').strip()
        else:
            audit_report = request.form.get('audit_report', '').strip()
        
        # Get other required fields
        observations = request.form.get('observations', '').strip()
        
        # Validate required fields
        error_message = None
        if not audit_reference:
            error_message = "Audit Reference is required"
        elif not audit_report:
            error_message = "Audit Report is required"
        elif not observations:
            error_message = "Observations are required"
        
        if error_message:
            conn.close()
            return render_template('add_finding.html', error=error_message)
        
        # Get target_date and clear it if status is Completed
        target_date = request.form.get('target_date', '').strip()
        status = request.form.get('status', '').strip()
        if status == 'Completed':
            target_date = None  # Clear target date for completed findings
        
        conn.execute('''
            INSERT INTO audit_findings (
                audit_reference, audit_report, observations, observation_details,
                report_date, priority, recommendation, management_response,
                target_date, revised_target_date, completion_date,
                person_responsible, department, status, validated,
                testing_procedures, comments, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            audit_reference,
            audit_report,
            observations,
            request.form.get('observation_details', ''),
            request.form.get('report_date', ''),
            request.form.get('priority', ''),
            request.form.get('recommendation', ''),
            request.form.get('management_response', ''),
            target_date,
            request.form.get('revised_target_date', ''),
            request.form.get('completion_date', ''),
            request.form.get('person_responsible', ''),
            request.form.get('department', ''),
            status,
            request.form.get('validated', ''),
            request.form.get('testing_procedures', ''),
            request.form.get('comments', ''),
            now
        ))
        conn.commit()
        conn.close()
        
        # Log the activity
        log_activity('ADD_FINDING', f'Added new finding: {audit_reference} - {audit_report[:50]}...')
        
        return redirect(url_for('index'))
    
    log_activity('VIEW_ADD_FORM', 'Accessed add finding form')
    return render_template('add_finding.html')

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@roles_required('superadmin', 'admin', 'editor')
def edit_finding(id):
    conn = get_db_connection()
    
    if request.method == 'POST':
        now = datetime.now().isoformat()
        
        # Handle conditional audit report field
        audit_reference = request.form.get('audit_reference', '')
        if audit_reference in ['24-07', '25-05']:
            audit_report = request.form.get('audit_report_custom', '')
        else:
            audit_report = request.form.get('audit_report', '')
        
        # Process status and target date - clear target date if status is Completed
        status = request.form.get('status', '')
        target_date = request.form.get('target_date', '')
        if status == 'Completed':
            target_date = ''
        
        conn.execute('''
            UPDATE audit_findings SET
                audit_reference=?, audit_report=?, observations=?, observation_details=?,
                report_date=?, priority=?, recommendation=?, management_response=?,
                target_date=?, revised_target_date=?, completion_date=?,
                person_responsible=?, department=?, status=?, validated=?,
                testing_procedures=?, comments=?, updated_at=?
            WHERE id=?
        ''', (
            audit_reference,
            audit_report,
            request.form.get('observations', ''),
            request.form.get('observation_details', ''),
            request.form.get('report_date', ''),
            request.form.get('priority', ''),
            request.form.get('recommendation', ''),
            request.form.get('management_response', ''),
            target_date,
            request.form.get('revised_target_date', ''),
            request.form.get('completion_date', ''),
            request.form.get('person_responsible', ''),
            request.form.get('department', ''),
            status,
            request.form.get('validated', ''),
            request.form.get('testing_procedures', ''),
            request.form.get('comments', ''),
            now,
            id
        ))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    
    finding = conn.execute('SELECT * FROM audit_findings WHERE id = ?', (id,)).fetchone()
    conn.close()
    return render_template('edit_finding.html', finding=finding)

@app.route('/delete/<int:id>', methods=['POST'])
@admin_required
def delete_finding(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM audit_findings WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

@app.route('/export')
@login_required
def export_csv():
    conn = get_db_connection()
    findings = conn.execute('SELECT * FROM audit_findings').fetchall()
    conn.close()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        'ID', 'Audit Reference', 'Audit Report', 'Observations', 'Observation Details',
        'Report Date', 'Priority', 'Recommendation', 'Management Response',
        'Target Date', 'Revised Target Date', 'Completion Date',
        'Person Responsible', 'Department', 'Status', 'Validated',
        'Testing Procedures', 'Comments', 'Created At', 'Updated At'
    ])
    
    # Write data
    for finding in findings:
        writer.writerow(finding)
    
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = f'attachment; filename=audit_findings_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    response.headers['Content-type'] = 'text/csv'
    return response

@app.route('/import', methods=['GET', 'POST'])
@roles_required('superadmin', 'admin', 'editor')
def import_findings():
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
        
        if file and file.filename.endswith('.csv'):
            # Process the CSV file
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            csv_input = csv.reader(stream)
            
            # Skip header row
            next(csv_input)
            
            conn = get_db_connection()
            imported_count = 0
            errors = []
            
            for row_num, row in enumerate(csv_input, start=2):
                if len(row) < 14:  # Ensure minimum required columns
                    errors.append(f"Row {row_num}: Insufficient columns")
                    continue
                
                try:
                    # Map CSV columns to database columns
                    # Your CSV: Audit Reference Number,Audit Report,Observations,Observation Details,Report Date,Priority,Recommendation,Management Response,Target Date,Revised Target Date,Completion Date,Person Responsible,Department of Person Responsible,Status,Validated,Testing Procedures,Comments
                    audit_reference = row[0].strip() if row[0] else ''
                    audit_report = row[1].strip() if row[1] else ''
                    observations = row[2].strip() if row[2] else ''
                    observation_details = row[3].strip() if row[3] else ''
                    report_date = row[4].strip() if row[4] else ''
                    priority = row[5].strip() if row[5] else ''
                    recommendation = row[6].strip() if row[6] else ''
                    management_response = row[7].strip() if row[7] else ''
                    target_date = row[8].strip() if row[8] else ''
                    revised_target_date = row[9].strip() if row[9] else ''
                    completion_date = row[10].strip() if row[10] else ''
                    person_responsible = row[11].strip() if row[11] else ''
                    department = row[12].strip() if row[12] else ''
                    status = row[13].strip() if row[13] else 'In-Progress'
                    validated = row[14].strip() if len(row) > 14 and row[14] else 'No'
                    testing_procedures = row[15].strip() if len(row) > 15 and row[15] else ''
                    comments = row[16].strip() if len(row) > 16 and row[16] else ''
                    
                    # Validate date fields - reject words, only accept proper dates or empty values
                    def validate_date(date_str, field_name):
                        if not date_str:
                            return ''
                        # Reject common non-date words
                        invalid_words = ['complete', 'na', 'n/a', 'pending', 'tbd', 'unknown']
                        if date_str.lower().strip() in invalid_words:
                            return ''  # Convert invalid words to empty string
                        # Check if it contains only date-like characters
                        if not all(c in '0123456789-/' for c in date_str):
                            raise ValueError(f"Invalid {field_name}: '{date_str}' contains non-date characters")
                        # Try parsing common date formats
                        try:
                            if '/' in date_str:
                                # Try MM/DD/YYYY or MM/DD/YY
                                parts = date_str.split('/')
                                if len(parts) == 3:
                                    if len(parts[2]) == 4:
                                        datetime.strptime(date_str, '%m/%d/%Y')
                                    else:
                                        datetime.strptime(date_str, '%m/%d/%y')
                            elif '-' in date_str:
                                # Try different dash formats
                                if len(date_str.split('-')[0]) == 4:
                                    datetime.strptime(date_str, '%Y-%m-%d')
                                else:
                                    # Try DD-MMM-YY format
                                    datetime.strptime(date_str, '%d-%b-%y')
                            return date_str
                        except ValueError:
                            raise ValueError(f"Invalid {field_name} format: '{date_str}'")
                    
                    # Clean person responsible field
                    def clean_person_responsible(person_str):
                        if not person_str:
                            return ''
                        # Take only the first line and first name/title
                        lines = person_str.split('\n')
                        first_line = lines[0].strip()
                        # If there's a comma, take only the part before the first comma
                        if ',' in first_line:
                            return first_line.split(',')[0].strip()
                        return first_line
                    
                    # Validate dates
                    target_date = validate_date(target_date, 'target date')
                    revised_target_date = validate_date(revised_target_date, 'revised target date')
                    completion_date = validate_date(completion_date, 'completion date')
                    report_date = validate_date(report_date, 'report date')
                    
                    # Clean person responsible field
                    person_responsible = clean_person_responsible(person_responsible)
                    
                    # Validate required fields
                    if not audit_reference.strip():
                        errors.append(f"Row {row_num}: Audit Reference is required")
                        continue
                    if not audit_report.strip():
                        errors.append(f"Row {row_num}: Audit Report is required")
                        continue
                    if not observations.strip():
                        errors.append(f"Row {row_num}: Observations are required")
                        continue
                    
                    # If status is Completed, target date is optional; otherwise it should be provided
                    if status.lower() != 'completed' and not target_date:
                        errors.append(f"Row {row_num}: Target date is required for non-completed findings")
                        continue
                    
                    # Insert into database
                    conn.execute('''
                        INSERT INTO audit_findings (
                            audit_reference, audit_report, observations, observation_details,
                            report_date, priority, recommendation, management_response,
                            target_date, revised_target_date, completion_date,
                            person_responsible, department, status, validated,
                            testing_procedures, comments, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        audit_reference, audit_report, observations, observation_details,
                        report_date, priority, recommendation, management_response,
                        target_date, revised_target_date, completion_date,
                        person_responsible, department, status, validated,
                        testing_procedures, comments, datetime.now().isoformat()
                    ))
                    imported_count += 1
                    
                except Exception as e:
                    errors.append(f"Row {row_num}: {str(e)}")
            
            conn.commit()
            conn.close()
            
            if errors:
                error_msg = f"Imported {imported_count} records with {len(errors)} errors: " + "; ".join(errors[:5])
                if len(errors) > 5:
                    error_msg += f" and {len(errors) - 5} more errors..."
                return render_template('import.html', message=error_msg, message_type='warning')
            else:
                return render_template('import.html', message=f"Successfully imported {imported_count} records!", message_type='success')
    
    return render_template('import.html')

@app.route('/api/chart-data/<int:year>')
@login_required
def get_chart_data(year):
    """API endpoint to get chart data for a specific year"""
    conn = get_db_connection()
    
    # Get all findings and filter by year in Python since date formats are inconsistent
    findings = conn.execute('''
        SELECT status, report_date, created_at
        FROM audit_findings 
    ''').fetchall()
    
    conn.close()
    
    # Initialize data structure
    data = {
        'Completed': 0,
        'In-Progress': 0,
        'Delayed': 0,
        'Closed': 0
    }
    
    # Function to extract year from various date formats
    def extract_year(date_str):
        if not date_str or date_str.strip() == '':
            return None
        
        # Handle formats like "17-Oct-24", "14-Jul-25", "8-May-24"
        date_patterns = [
            r'(\d{1,2})-(\w{3})-(\d{2})',  # 17-Oct-24
            r'(\d{1,2})/(\d{1,2})/(\d{2,4})',  # 17/10/24 or 17/10/2024
            r'(\d{4})-(\d{2})-(\d{2})',  # 2024-10-17
        ]
        
        for pattern in date_patterns:
            match = re.match(pattern, date_str)
            if match:
                if pattern == date_patterns[0]:  # DD-MMM-YY format
                    year_str = match.group(3)
                    # Convert 2-digit year to 4-digit
                    if len(year_str) == 2:
                        year_int = int(year_str)
                        if year_int >= 20:  # 20-99 -> 2020-2099
                            return 2000 + year_int
                        else:  # 00-19 -> 2000-2019
                            return 2000 + year_int
                    else:
                        return int(year_str)
                elif pattern == date_patterns[1]:  # MM/DD/YY or MM/DD/YYYY
                    year_str = match.group(3)
                    if len(year_str) == 2:
                        year_int = int(year_str)
                        if year_int >= 20:
                            return 2000 + year_int
                        else:
                            return 2000 + year_int
                    else:
                        return int(year_str)
                elif pattern == date_patterns[2]:  # YYYY-MM-DD
                    return int(match.group(1))
        
        return None
    
    # Filter findings by year
    for finding in findings:
        # Try to get year from report_date first
        finding_year = extract_year(finding['report_date'])
        
        # If report_date doesn't give us a year, use created_at
        if finding_year is None:
            try:
                # Extract year from created_at (ISO format)
                if finding['created_at']:
                    finding_year = int(finding['created_at'][:4])
            except (TypeError, ValueError):
                finding_year = None
        
        # If this finding belongs to the requested year, count it
        if finding_year == year and finding['status'] in data:
            data[finding['status']] += 1
    
    return jsonify(data)

@app.route('/api/findings-by-status/<status>/<int:year>')
@login_required
def get_findings_by_status(status, year):
    """API endpoint to get findings by status and year"""
    conn = get_db_connection()
    
    # Get all findings with the specified status
    findings = conn.execute('''
        SELECT id, audit_reference, audit_report, status, priority, 
               target_date, person_responsible, created_at, report_date
        FROM audit_findings 
        WHERE status = ?
        ORDER BY created_at DESC
    ''', (status,)).fetchall()
    
    conn.close()
    
    # Function to extract year from various date formats
    def extract_year(date_str):
        if not date_str or date_str.strip() == '':
            return None
        
        # Handle formats like "17-Oct-24", "14-Jul-25", "8-May-24"
        date_patterns = [
            r'(\d{1,2})-(\w{3})-(\d{2})',  # 17-Oct-24
            r'(\d{1,2})/(\d{1,2})/(\d{2,4})',  # 17/10/24 or 17/10/2024
            r'(\d{4})-(\d{2})-(\d{2})',  # 2024-10-17
        ]
        
        for pattern in date_patterns:
            match = re.match(pattern, date_str)
            if match:
                if pattern == date_patterns[0]:  # DD-MMM-YY format
                    year_str = match.group(3)
                    # Convert 2-digit year to 4-digit
                    if len(year_str) == 2:
                        year_int = int(year_str)
                        if year_int >= 20:  # 20-99 -> 2020-2099
                            return 2000 + year_int
                        else:  # 00-19 -> 2000-2019
                            return 2000 + year_int
                    else:
                        return int(year_str)
                elif pattern == date_patterns[1]:  # MM/DD/YY or MM/DD/YYYY
                    year_str = match.group(3)
                    if len(year_str) == 2:
                        year_int = int(year_str)
                        if year_int >= 20:
                            return 2000 + year_int
                        else:
                            return 2000 + year_int
                    else:
                        return int(year_str)
                elif pattern == date_patterns[2]:  # YYYY-MM-DD
                    return int(match.group(1))
        
        return None
    
    # Filter findings by year and convert to list of dictionaries
    findings_list = []
    for finding in findings:
        # Try to get year from report_date first
        finding_year = extract_year(finding['report_date'])
        
        # If report_date doesn't give us a year, use created_at
        if finding_year is None:
            try:
                # Extract year from created_at (ISO format)
                if finding['created_at']:
                    finding_year = int(finding['created_at'][:4])
            except (TypeError, ValueError):
                finding_year = None
        
        # If this finding belongs to the requested year, include it
        if finding_year == year:
            findings_list.append({
                'id': finding['id'],
                'audit_reference': finding['audit_reference'],
                'audit_report': finding['audit_report'],
                'status': finding['status'],
                'priority': finding['priority'],
                'target_date': finding['target_date'],
                'person_responsible': finding['person_responsible'],
                'created_at': finding['created_at'],
                'report_date': finding['report_date']
            })
    
    return jsonify(findings_list)

@app.route('/api/finding/<int:finding_id>')
@login_required
def get_finding_details(finding_id):
    conn = get_db_connection()
    finding = conn.execute('''
        SELECT * FROM audit_findings WHERE id = ?
    ''', (finding_id,)).fetchone()
    conn.close()
    
    if finding:
        finding_dict = {
            'id': finding['id'],
            'audit_reference': finding['audit_reference'],
            'audit_report': finding['audit_report'],
            'observations': finding['observations'],
            'observation_details': finding['observation_details'],
            'report_date': finding['report_date'],
            'priority': finding['priority'],
            'recommendation': finding['recommendation'],
            'management_response': finding['management_response'],
            'target_date': finding['target_date'],
            'revised_target_date': finding['revised_target_date'],
            'completion_date': finding['completion_date'],
            'person_responsible': finding['person_responsible'],
            'department': finding['department'],
            'status': finding['status'],
            'validated': finding['validated'],
            'testing_procedures': finding['testing_procedures'],
            'comments': finding['comments'],
            'created_at': finding['created_at'],
            'updated_at': finding['updated_at']
        }
        return jsonify(finding_dict)
    else:
        return jsonify({'error': 'Finding not found'}), 404

@app.route('/download-template/<format>')
@login_required
def download_template(format):
    """Download template file for import"""
    log_activity('DOWNLOAD_TEMPLATE', f'Downloaded {format} template')
    
    # Define template headers
    headers = [
        'Audit Reference', 'Audit Report', 'Observations', 'Observation Details',
        'Report Date', 'Priority', 'Recommendation', 'Management Response',
        'Target Date', 'Revised Target Date', 'Completion Date',
        'Person Responsible', 'Department', 'Status', 'Validated',
        'Testing Procedures', 'Comments'
    ]
    
    if format.lower() == 'csv':
        # Create CSV template
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(headers)
        
        # Add sample row
        sample_row = [
            'AUDIT-2024-001', 'Internal Audit Report', 'Sample observation text',
            'Additional details about the observation', '2024-12-15', 'High',
            'Recommended action to address the finding', 'Management agrees with the recommendation',
            '2025-01-15', '', '', 'John Doe', 'Finance Department',
            'In-Progress', 'No', 'Testing procedures used', 'Additional comments'
        ]
        writer.writerow(sample_row)
        
        response = make_response(output.getvalue())
        response.headers['Content-Disposition'] = 'attachment; filename=audit_findings_template.csv'
        response.headers['Content-Type'] = 'text/csv'
        return response
    
    elif format.lower() == 'xlsx':
        workbook = Workbook()
        worksheet = workbook.active
        worksheet.title = 'Audit Findings'
        worksheet.append(headers)
        
        # Add sample row
        sample_row = [
            'AUDIT-2024-001', 'Internal Audit Report', 'Sample observation text',
            'Additional details about the observation', '2024-12-15', 'High',
            'Recommended action to address the finding', 'Management agrees with the recommendation',
            '2025-01-15', '', '', 'John Doe', 'Finance Department',
            'In-Progress', 'No', 'Testing procedures used', 'Additional comments'
        ]
        worksheet.append(sample_row)
        
        output = io.BytesIO()
        workbook.save(output)
        response = make_response(output.getvalue())
        response.headers['Content-Disposition'] = 'attachment; filename=audit_findings_template.xlsx'
        response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        return response
    
    else:
        flash('Invalid template format requested', 'error')
        return redirect(url_for('import_findings'))

# Context processor to make variables available to all templates
@app.context_processor
def inject_template_vars():
    """Inject template variables available to all templates"""
    context = {}
    
    # Check if current user must change password
    if 'username' in session:
        user = get_user_from_db(session['username'])
        if user:
            context['user_must_change_password'] = user.get('must_change_password', False)
        else:
            context['user_must_change_password'] = False
    else:
        context['user_must_change_password'] = False

    context['user_alerts'] = []
    if session.get('username'):
        conn = get_db_connection()
        alerts = conn.execute(
            'SELECT id, sender, message, created_at FROM user_alerts '
            'WHERE recipient = ? AND read_at IS NULL ORDER BY created_at DESC LIMIT 5',
            (session['username'],),
        ).fetchall()
        conn.close()
        context['user_alerts'] = [dict(alert) for alert in alerts]
    
    return context

if __name__ == '__main__':
    # Get port from environment variable (for cloud deployments) or default to 5000
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '0.0.0.0')  # Bind to all interfaces for cloud deployment
    debug = os.environ.get('FLASK_DEBUG', '').lower() in {'1', 'true', 'yes'} and not IS_PRODUCTION
    
    print("🚀 Starting Internal Audit Tracker...")
    print("📊 Database initialized successfully!")
    print(f"🌐 Server running at: http://{host}:{port}")
    print("Press CTRL+C to stop the server")
    
    app.run(debug=debug, host=host, port=port)
