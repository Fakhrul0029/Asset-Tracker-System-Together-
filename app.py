"""
JTDI Asset Tracker System - Production Ready
A beautifully structured Flask application for tracking hardware assets.
"""

import os
import io
import csv
import base64
import json
import traceback
import uuid
import time
import qrcode
import psycopg2
import psycopg2.extras
import psycopg2.pool
import pandas as pd
import logging
from logging.handlers import RotatingFileHandler
from functools import wraps
from typing import Optional, Tuple, Dict, Any, Callable
from contextlib import contextmanager
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, Response, g, jsonify
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

# ============================================================================
# Configuration
# ============================================================================

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'jtdi_secure_master_2026')
app.permanent_session_lifetime = timedelta(hours=8)

# Enable CSRF protection
csrf = CSRFProtect(app)

DATABASE_URL = os.environ.get('DATABASE_URL')

# Configure connection pooling
connection_pool = psycopg2.pool.SimpleConnectionPool(
    minconn=1,
    maxconn=10,
    dsn=DATABASE_URL
)

# Configure logging
if not os.path.exists('logs'):
    os.makedirs('logs')
file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: [%(request_id)s] %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Asset Tracker startup')

# In-memory rate limiting for login attempts
login_attempts: Dict[str, list] = {}

# ============================================================================
# Custom Exceptions
# ============================================================================

class AssetTrackerError(Exception):
    """Base exception for Asset Tracker errors"""
    pass

class AuthenticationError(AssetTrackerError):
    """Authentication related errors"""
    pass

class AuthorizationError(AssetTrackerError):
    """Authorization related errors"""
    pass

class ValidationError(AssetTrackerError):
    """Validation related errors"""
    pass

class DatabaseError(AssetTrackerError):
    """Database related errors"""
    pass

# ============================================================================
# Database Connection Management
# ============================================================================

def get_db_connection():
    """Get a database connection from the pool with fallback to direct connection."""
    url = DATABASE_URL
    if url and url.startswith('postgres://'):
        url = url.replace('postgres://', 'postgresql://', 1)
    try:
        return connection_pool.getconn()
    except Exception:
        app.logger.warning("Connection pool failed, using direct connection")
        return psycopg2.connect(url)


def release_db_connection(conn):
    """Release a database connection back to the pool."""
    try:
        connection_pool.putconn(conn)
    except Exception:
        conn.close()


@contextmanager
def db_connection():
    """Context manager for database connections with automatic cleanup."""
    conn = get_db_connection()
    try:
        yield conn
    finally:
        release_db_connection(conn)


@contextmanager
def db_cursor(dict_cursor: bool = False):
    """Context manager for database cursors with automatic cleanup."""
    conn = get_db_connection()
    try:
        cursor_factory = psycopg2.extras.DictCursor if dict_cursor else None
        cur = conn.cursor(cursor_factory=cursor_factory)
        try:
            yield cur, conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()
    finally:
        release_db_connection(conn)

# ============================================================================
# Utility Functions
# ============================================================================

def is_admin() -> bool:
    """Check if current user has admin role."""
    return session.get('role') == 'Admin'


def is_authenticated() -> bool:
    """Check if user is authenticated."""
    return 'user' in session


def validate_password_complexity(password: str) -> Tuple[bool, str]:
    """
    Validate password complexity requirements.
    
    Args:
        password: Password string to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"
    return True, "Password is valid"


def check_rate_limit(email: str) -> Tuple[bool, Optional[str]]:
    """
    Check if login attempts exceed rate limit (5 attempts per 15 minutes).
    
    Args:
        email: User email to check
        
    Returns:
        Tuple of (is_allowed, error_message)
    """
    now = datetime.now()
    if email in login_attempts:
        attempts = login_attempts[email]
        # Remove attempts older than 15 minutes
        attempts = [t for t in attempts if (now - t).total_seconds() < 900]
        login_attempts[email] = attempts
        if len(attempts) >= 5:
            return False, "Too many login attempts. Please try again in 15 minutes."
    else:
        login_attempts[email] = []
    return True, None


def log_activity(user_label: str, action: str, asset_serial: Optional[str] = None) -> None:
    """Log user activity to database."""
    try:
        with db_cursor() as (cur, conn):
            cur.execute(
                "INSERT INTO activity_logs (user_email, action, asset_serial) VALUES (%s,%s,%s)",
                (user_label, action, asset_serial)
            )
    except Exception as e:
        app.logger.error(f"ACTIVITY LOG ERROR: {e}")


def log_access(email: str, action: str) -> None:
    """Log user access events to database."""
    try:
        with db_cursor() as (cur, conn):
            cur.execute(
                "INSERT INTO access_logs (user_email, action) VALUES (%s,%s)",
                (email, action)
            )
    except Exception as e:
        app.logger.error(f"ACCESS LOG ERROR: {e}")

# ============================================================================
# Decorators
# ============================================================================

def login_required(f: Callable) -> Callable:
    """Decorator to require user login for routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_authenticated():
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f: Callable) -> Callable:
    """Decorator to require admin role for routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_admin():
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def handle_errors(f: Callable) -> Callable:
    """Decorator to handle common errors in routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except AuthenticationError as e:
            app.logger.warning(f"Authentication error: {e}")
            flash(str(e))
            return redirect(url_for('login'))
        except AuthorizationError as e:
            app.logger.warning(f"Authorization error: {e}")
            flash(str(e))
            return redirect(url_for('dashboard'))
        except ValidationError as e:
            app.logger.warning(f"Validation error: {e}")
            flash(str(e))
            return redirect(request.url or url_for('dashboard'))
        except DatabaseError as e:
            app.logger.error(f"Database error: {e}")
            flash("A database error occurred. Please try again.")
            return redirect(url_for('dashboard'))
        except Exception as e:
            app.logger.error(f"Unexpected error in {f.__name__}: {e}")
            flash("An unexpected error occurred. Please try again.")
            return redirect(url_for('dashboard'))
    return decorated_function

# ============================================================================
# Middleware
# ============================================================================

@app.before_request
def add_request_id():
    """Add unique request ID to each request for tracing."""
    g.request_id = str(uuid.uuid4())[:8]
    g.start_time = time.time()


@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


@app.after_request
def log_request_duration(response):
    """Log request duration for performance monitoring."""
    if hasattr(g, 'start_time'):
        duration = time.time() - g.start_time
        if duration > 1.0:  # Log slow requests
            app.logger.warning(f"Slow request: {request.path} took {duration:.2f}s")
    return response

# ============================================================================
# Database Initialization
# ============================================================================

def ensure_bootstrap_admin() -> None:
    """Ensure bootstrap admin user exists."""
    email = os.environ.get('BOOTSTRAP_ADMIN_EMAIL', 'admin@jtdi.gov.my').strip().lower()
    password = os.environ.get('BOOTSTRAP_ADMIN_PASSWORD', 'admin123')
    username = os.environ.get('BOOTSTRAP_ADMIN_USERNAME', 'admin')
    full_name = os.environ.get('BOOTSTRAP_ADMIN_NAME', 'System Administrator')
    hashed = generate_password_hash(password)

    with db_cursor(dict_cursor=True) as (cur, conn):
        cur.execute(
            "SELECT id FROM users WHERE username = %s OR email = %s",
            (username, email)
        )
        row = cur.fetchone()
        if row:
            cur.execute("""
                UPDATE users
                SET full_name = %s, email = %s, password = %s, role = 'Admin'
                WHERE id = %s
            """, (full_name, email, hashed, row['id']))
        else:
            cur.execute("""
                INSERT INTO users (full_name, username, email, password, role)
                VALUES (%s, %s, %s, %s, 'Admin')
            """, (full_name, username, email, hashed))


def init_db() -> None:
    """Initialize database schema with all required tables and indexes."""
    with db_cursor() as (cur, conn):
        # Assets table
        cur.execute('''CREATE TABLE IF NOT EXISTS assets (
            id SERIAL PRIMARY KEY,
            asset_type TEXT,
            tracking_number TEXT,
            cpu_name TEXT,
            serial_number TEXT UNIQUE,
            ram_size TEXT,
            storage_type TEXT,
            location TEXT,
            status TEXT,
            description TEXT,
            is_deleted BOOLEAN DEFAULT FALSE,
            scan_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            assigned_to TEXT,
            checkout_date TIMESTAMP,
            checkout_by TEXT
        );''')

        # Add columns if they don't exist
        cur.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS description TEXT;")
        cur.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS scan_count INTEGER DEFAULT 0;")
        cur.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN DEFAULT FALSE;")
        cur.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS assigned_to TEXT;")
        cur.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS checkout_date TIMESTAMP;")
        cur.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS checkout_by TEXT;")

        # Database indexes for performance
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_assets_serial ON assets(serial_number);",
            "CREATE INDEX IF NOT EXISTS idx_assets_tracking ON assets(tracking_number);",
            "CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);",
            "CREATE INDEX IF NOT EXISTS idx_assets_location ON assets(location);",
            "CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type);",
            "CREATE INDEX IF NOT EXISTS idx_assets_deleted ON assets(is_deleted);",
            "CREATE INDEX IF NOT EXISTS idx_assets_assigned ON assets(assigned_to);",
            "CREATE INDEX IF NOT EXISTS idx_activity_created ON activity_logs(created_at);",
            "CREATE INDEX IF NOT EXISTS idx_login_time ON login_logs(login_time);"
        ]
        for index in indexes:
            cur.execute(index)

        # Maintenance logs table
        cur.execute('''CREATE TABLE IF NOT EXISTS maintenance_logs (
            id SERIAL PRIMARY KEY,
            asset_id INTEGER REFERENCES assets(id),
            action_type TEXT,
            comment TEXT,
            updated_by TEXT,
            log_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );''')

        # Users table
        cur.execute('''CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            full_name TEXT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'User'
        );''')
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name TEXT;")

        # Login logs table
        cur.execute('''CREATE TABLE IF NOT EXISTS login_logs (
            id SERIAL PRIMARY KEY,
            full_name TEXT,
            email TEXT,
            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );''')

        # Activity logs table
        cur.execute('''CREATE TABLE IF NOT EXISTS activity_logs (
            id SERIAL PRIMARY KEY,
            user_email TEXT,
            action TEXT,
            asset_serial TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );''')

        # Access logs table
        cur.execute('''CREATE TABLE IF NOT EXISTS access_logs (
            id SERIAL PRIMARY KEY,
            user_email TEXT,
            action TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );''')


def safe_startup() -> None:
    """Safely initialize the application on startup."""
    if not DATABASE_URL:
        app.logger.warning("DATABASE_URL is not set. DB init and bootstrap skipped.")
        return
    try:
        init_db()
        ensure_bootstrap_admin()
        app.logger.info(f"Startup OK. Bootstrap admin: {os.environ.get('BOOTSTRAP_ADMIN_EMAIL', 'admin@jtdi.gov.my')}")
    except Exception as e:
        app.logger.error(f"STARTUP ERROR: {e}")
        traceback.print_exc()

safe_startup()

# ============================================================================
# Health Check Endpoint
# ============================================================================

@app.route('/health')
def health_check():
    """Health check endpoint for monitoring."""
    try:
        with db_cursor() as (cur, conn):
            cur.execute("SELECT 1")
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'database': 'connected'
        }), 200
    except Exception as e:
        app.logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.now().isoformat(),
            'database': 'disconnected',
            'error': str(e)
        }), 503

# ============================================================================
# Authentication Routes
# ============================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login with rate limiting."""
    if request.method == 'POST':
        session.clear()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        # Rate limiting check
        allowed, error_msg = check_rate_limit(email)
        if not allowed:
            flash(error_msg)
            return render_template('login.html')

        try:
            with db_cursor(dict_cursor=True) as (cur, conn):
                cur.execute("SELECT * FROM users WHERE email = %s", (email,))
                user = cur.fetchone()

                if user and check_password_hash(user['password'], password):
                    # Clear login attempts on successful login
                    if email in login_attempts:
                        del login_attempts[email]

                    session.permanent = True
                    session.update({
                        'user': user['username'],
                        'role': user['role'],
                        'full_name': user['full_name'] or user['username'],
                        'email': user['email']
                    })
                    cur.execute(
                        "INSERT INTO login_logs (full_name, email) VALUES (%s, %s)",
                        (user['full_name'] or user['username'], user['email'])
                    )
                    log_access(user['email'], "LOGIN")
                    app.logger.info(f"User logged in: {email}")
                    return redirect(url_for('dashboard'))
                else:
                    # Record failed login attempt
                    if email not in login_attempts:
                        login_attempts[email] = []
                    login_attempts[email].append(datetime.now())
                    app.logger.warning(f"Failed login attempt for: {email}")

            flash("Invalid email or password.")
        except Exception as e:
            app.logger.error(f"Login error: {e}")
            flash("An error occurred during login. Please try again.")

    return render_template('login.html')


@app.route('/logout')
def logout():
    """Handle user logout."""
    if session.get('email'):
        log_access(session['email'], "LOGOUT")
    session.clear()
    return redirect(url_for('login'))

# ============================================================================
# Dashboard Routes
# ============================================================================

@app.route('/dashboard')
@login_required
@handle_errors
def dashboard():
    """Display dashboard with asset statistics."""
    with db_cursor(dict_cursor=True) as (cur, conn):
        # Get statistics
        cur.execute("SELECT COUNT(*) FROM assets WHERE is_deleted = FALSE")
        total = cur.fetchone()['count']
        
        cur.execute("SELECT COUNT(*) FROM assets WHERE status = 'Working' AND is_deleted = FALSE")
        working = cur.fetchone()['count']
        
        cur.execute("SELECT COUNT(*) FROM assets WHERE status = 'Maintenance' AND is_deleted = FALSE")
        maint = cur.fetchone()['count']
        
        cur.execute("SELECT COUNT(*) FROM assets WHERE status = 'Faulty' AND is_deleted = FALSE")
        faulty = cur.fetchone()['count']
        
        cur.execute("SELECT COUNT(*) FROM assets WHERE assigned_to IS NOT NULL AND is_deleted = FALSE")
        checked_out = cur.fetchone()['count']
        
        # Assets by type
        cur.execute("SELECT asset_type, COUNT(*) as count FROM assets WHERE is_deleted = FALSE GROUP BY asset_type")
        by_type = cur.fetchall()
        
        # Assets by location
        cur.execute("SELECT location, COUNT(*) as count FROM assets WHERE is_deleted = FALSE GROUP BY location")
        by_location = cur.fetchall()
        
        # Recent activity
        cur.execute("SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT 10")
        recent_activity = cur.fetchall()

    return render_template('dashboard.html', 
                         total=total, working=working, maint=maint, faulty=faulty, 
                         checked_out=checked_out, by_type=by_type, by_location=by_location,
                         recent_activity=recent_activity)

# ============================================================================
# Asset Routes
# ============================================================================

@app.route('/')
@login_required
@handle_errors
def index():
    """Display assets list with search, filter, sort, and pagination."""
    s = request.args.get('search', '').strip()
    c = request.args.get('category', '').strip()
    sort = request.args.get('sort', 'id')
    order = request.args.get('order', 'desc')
    page = request.args.get('page', 1, type=int)
    per_page = 20

    with db_cursor(dict_cursor=True) as (cur, conn):
        query = "SELECT * FROM assets WHERE 1=1"
        count_query = "SELECT COUNT(*) FROM assets WHERE 1=1"
        params = []
        
        if session.get('role') != 'Admin':
            query += " AND is_deleted = FALSE"
            count_query += " AND is_deleted = FALSE"
        
        if s:
            query += (
                " AND (serial_number ILIKE %s OR tracking_number ILIKE %s "
                "OR cpu_name ILIKE %s OR location ILIKE %s)"
            )
            count_query += (
                " AND (serial_number ILIKE %s OR tracking_number ILIKE %s "
                "OR cpu_name ILIKE %s OR location ILIKE %s)"
            )
            p = f'%{s}%'
            params.extend([p, p, p, p])
        
        if c:
            query += " AND asset_type = %s"
            count_query += " AND asset_type = %s"
            params.append(c)

        # Get total count for pagination
        cur.execute(count_query, tuple(params))
        total = cur.fetchone()['count']
        
        # Add sorting
        valid_sorts = ['id', 'tracking_number', 'cpu_name', 'serial_number', 'status', 'location', 'asset_type']
        if sort not in valid_sorts:
            sort = 'id'
        order_dir = 'DESC' if order.lower() == 'desc' else 'ASC'
        query += f" ORDER BY {sort} {order_dir}"
        
        # Add pagination
        offset = (page - 1) * per_page
        query += f" LIMIT {per_page} OFFSET {offset}"
        
        cur.execute(query, tuple(params))
        data = cur.fetchall()

    stats = {
        'total': total,
        'working': len([r for r in data if r['status'] == 'Working']),
        'maint': len([r for r in data if r['status'] == 'Maintenance']),
        'faulty': len([r for r in data if r['status'] == 'Faulty'])
    }
    
    total_pages = (total + per_page - 1) // per_page

    return render_template('assets.html', data=data, **stats, s_query=s, c_filter=c,
                         sort=sort, order=order, page=page, total_pages=total_pages, per_page=per_page)


@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
@handle_errors
def edit_asset(id: int):
    """Edit an existing asset."""
    with db_cursor(dict_cursor=True) as (cur, conn):
        if request.method == 'POST':
            cur.execute("""
                UPDATE assets SET
                    asset_type=%s,
                    tracking_number=%s,
                    cpu_name=%s,
                    ram_size=%s,
                    storage_type=%s,
                    location=%s,
                    status=%s,
                    description=%s
                WHERE id=%s
            """, (
                request.form.get('asset_type'),
                request.form.get('tracking_number'),
                request.form.get('cpu_name'),
                request.form.get('ram_size'),
                request.form.get('storage_type'),
                request.form.get('location'),
                request.form.get('status'),
                request.form.get('description'),
                id
            ))

            comment = request.form.get('comment', '').strip()
            if comment:
                cur.execute("""
                    INSERT INTO maintenance_logs (asset_id, action_type, comment, updated_by)
                    VALUES (%s, %s, %s, %s)
                """, (
                    id,
                    request.form.get('action_type'),
                    comment,
                    session.get('full_name')
                ))

            cur.execute("SELECT serial_number FROM assets WHERE id = %s", (id,))
            row = cur.fetchone()

            log_activity(
                session.get('email') or session.get('full_name'),
                "ASSET UPDATED",
                row['serial_number'] if row else None
            )
            app.logger.info(f"Asset updated: {id}")
            flash("Update Saved!")
            return redirect(url_for('index'))

        cur.execute("SELECT * FROM assets WHERE id = %s", (id,))
        asset = cur.fetchone()

    if not asset:
        flash("Asset not found.")
        return redirect(url_for('index'))

    return render_template('edit.html', asset=asset)


@app.route('/view/<int:id>')
def view_asset(id: int):
    """View asset details."""
    try:
        with db_cursor(dict_cursor=True) as (cur, conn):
            cur.execute("SELECT * FROM assets WHERE id = %s", (id,))
            asset = cur.fetchone()
            if not asset:
                return "Not Found", 404

            cur.execute(
                "UPDATE assets SET scan_count = COALESCE(scan_count, 0) + 1 WHERE id = %s",
                (id,)
            )
            cur.execute(
                "SELECT * FROM maintenance_logs WHERE asset_id = %s ORDER BY log_date DESC",
                (id,)
            )
            logs = cur.fetchall()

        return render_template('view.html', asset=asset, logs=logs)
    except Exception as e:
        app.logger.error(f"View asset error: {e}")
        flash("An error occurred loading the asset.")
        return redirect(url_for('index'))


@app.route('/asset/<int:id>')
def legacy_asset_view(id: int):
    """Legacy route for asset viewing - redirects to new route."""
    return redirect(url_for('view_asset', id=id))


@app.route('/qr/<int:id>')
@login_required
@handle_errors
def qr_code(id: int):
    """Generate QR code for an asset."""
    with db_cursor(dict_cursor=True) as (cur, conn):
        cur.execute("SELECT * FROM assets WHERE id = %s", (id,))
        asset = cur.fetchone()

    if not asset:
        flash("Asset not found.")
        return redirect(url_for('index'))

    qr_url = url_for('view_asset', id=id, _external=True)
    img = qrcode.make(qr_url)
    buf = io.BytesIO()
    img.save(buf)
    qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')

    return render_template('qr_display.html', qr_code=qr_b64, asset=asset)


@app.route('/checkout/<int:id>', methods=['POST'])
@login_required
@handle_errors
def checkout_asset(id: int):
    """Check out an asset to a user."""
    assigned_to = request.form.get('assigned_to', '').strip()
    if not assigned_to:
        raise ValidationError("Please specify who is checking out this asset.")

    with db_cursor(dict_cursor=True) as (cur, conn):
        cur.execute("SELECT serial_number FROM assets WHERE id = %s", (id,))
        row = cur.fetchone()
        
        cur.execute("""
            UPDATE assets SET 
                assigned_to = %s,
                checkout_date = %s,
                checkout_by = %s
            WHERE id = %s
        """, (assigned_to, datetime.now(), session.get('full_name'), id))

        if row:
            log_activity(
                session.get('email') or session.get('full_name'),
                f"ASSET CHECKED OUT TO {assigned_to}",
                row['serial_number']
            )
            app.logger.info(f"Asset checked out: {id} to {assigned_to}")
        
    flash(f"Asset checked out to {assigned_to}.")
    return redirect(url_for('index'))


@app.route('/checkin/<int:id>', methods=['POST'])
@login_required
@handle_errors
def checkin_asset(id: int):
    """Check in an asset."""
    with db_cursor(dict_cursor=True) as (cur, conn):
        cur.execute("SELECT serial_number, assigned_to FROM assets WHERE id = %s", (id,))
        row = cur.fetchone()
        
        cur.execute("""
            UPDATE assets SET 
                assigned_to = NULL,
                checkout_date = NULL,
                checkout_by = NULL
            WHERE id = %s
        """, (id,))

        if row:
            log_activity(
                session.get('email') or session.get('full_name'),
                f"ASSET CHECKED IN FROM {row['assigned_to'] or 'unknown'}",
                row['serial_number']
            )
            app.logger.info(f"Asset checked in: {id}")
        
    flash("Asset checked in successfully.")
    return redirect(url_for('index'))


@app.route('/delete/<int:id>', methods=['POST'])
@login_required
@handle_errors
def delete_asset(id: int):
    """Archive an asset (soft delete)."""
    with db_cursor(dict_cursor=True) as (cur, conn):
        cur.execute("SELECT serial_number FROM assets WHERE id = %s", (id,))
        row = cur.fetchone()
        cur.execute("UPDATE assets SET is_deleted = TRUE WHERE id = %s", (id,))

        if row:
            log_activity(
                session.get('email') or session.get('full_name'),
                "ASSET ARCHIVED",
                row['serial_number']
            )
            app.logger.info(f"Asset archived: {id}")
        
    flash("Asset archived.")
    return redirect(url_for('index'))


@app.route('/add', methods=['GET', 'POST'])
@login_required
@handle_errors
def add_asset():
    """Add a new asset."""
    if request.method == 'POST':
        with db_cursor() as (cur, conn):
            tn = (request.form.get('tracking_number') or '').strip()
            if not tn:
                tn = f"JTDI-{datetime.now().strftime('%y%m%H%M%S')}"

            cur.execute("""
                INSERT INTO assets (
                    asset_type, tracking_number, cpu_name, serial_number,
                    ram_size, storage_type, status, location, description, is_deleted
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s, FALSE)
            """, (
                request.form.get('asset_type'),
                tn,
                request.form.get('cpu_name'),
                request.form.get('serial_number'),
                request.form.get('ram_size'),
                request.form.get('storage_type'),
                request.form.get('status'),
                request.form.get('location'),
                request.form.get('description')
            ))

            log_activity(
                session.get('email') or session.get('full_name'),
                "ASSET REGISTERED",
                request.form.get('serial_number')
            )
            app.logger.info(f"Asset added: {request.form.get('serial_number')}")

        return redirect(url_for('index'))

    return render_template('add.html')

# ============================================================================
# Activity & Export Routes
# ============================================================================

@app.route('/activity')
@login_required
@handle_errors
def activity():
    """Display activity logs."""
    with db_cursor(dict_cursor=True) as (cur, conn):
        cur.execute("SELECT * FROM activity_logs ORDER BY created_at DESC")
        logs = cur.fetchall()

    return render_template('activity.html', logs=logs)


@app.route('/export')
@login_required
@handle_errors
def export_csv():
    """Export assets to CSV format."""
    with db_cursor() as (cur, conn):
        query = "SELECT * FROM assets WHERE 1=1"
        if session.get('role') != 'Admin':
            query += " AND is_deleted = FALSE"
        query += " ORDER BY id DESC"
        cur.execute(query)
        rows = cur.fetchall()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([d[0] for d in cur.description])
        writer.writerows(rows)
        output.seek(0)

        app.logger.info("CSV export completed")
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment;filename=assets.csv"}
        )


@app.route('/export/excel')
@login_required
@handle_errors
def export_excel():
    """Export assets to Excel format."""
    with db_cursor() as (cur, conn):
        query = "SELECT * FROM assets WHERE 1=1"
        if session.get('role') != 'Admin':
            query += " AND is_deleted = FALSE"
        query += " ORDER BY id DESC"
        
        cur.execute(query)
        column_names = [desc[0] for desc in cur.description]
        rows = cur.fetchall()

        # Convert rows to list of dicts for better handling
        data = [dict(zip(column_names, row)) for row in rows]
        df = pd.DataFrame(data)
        
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Assets')
        output.seek(0)

        app.logger.info("Excel export completed")
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=f"Assets_{datetime.now().strftime('%Y%m%d')}.xlsx"
        )

# ============================================================================
# Admin Routes
# ============================================================================

@app.route('/admin')
@admin_required
@handle_errors
def admin_dashboard():
    """Display admin dashboard with user, access, and login logs."""
    with db_cursor(dict_cursor=True) as (cur, conn):
        cur.execute("SELECT * FROM users ORDER BY id DESC")
        users = cur.fetchall()
        cur.execute("SELECT * FROM access_logs ORDER BY created_at DESC LIMIT 25")
        access_logs = cur.fetchall()
        cur.execute("SELECT * FROM login_logs ORDER BY login_time DESC LIMIT 100")
        login_logs = cur.fetchall()

    return render_template('admin.html', users=users, access_logs=access_logs, login_logs=login_logs)


@app.route('/admin/users', methods=['GET', 'POST'])
@admin_required
@handle_errors
def manage_users():
    """Manage user accounts - redirects to admin panel."""
    if request.method == 'POST':
        role = request.form.get('role', 'User')
        if role not in ('User', 'Admin'):
            role = 'User'
        
        password = request.form.get('password', '')
        # Validate password complexity
        valid, error_msg = validate_password_complexity(password)
        if not valid:
            raise ValidationError(error_msg)
        
        with db_cursor(dict_cursor=True) as (cur, conn):
            cur.execute("""
                INSERT INTO users (full_name, username, email, password, role)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                request.form.get('full_name') or request.form.get('username'),
                request.form.get('username'),
                request.form.get('email', '').strip().lower(),
                generate_password_hash(password),
                role
            ))
            app.logger.info(f"User created: {request.form.get('email')}")
            flash("User created successfully.")

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/edit_user/<int:id>', methods=['GET', 'POST'])
@admin_required
@handle_errors
def edit_user(id: int):
    """Edit user account."""
    with db_cursor(dict_cursor=True) as (cur, conn):
        if request.method == 'POST':
            role = request.form.get('role', 'User')
            if role not in ('User', 'Admin'):
                role = 'User'
            new_password = request.form.get('password', '').strip()

            if new_password:
                # Validate password complexity
                valid, error_msg = validate_password_complexity(new_password)
                if not valid:
                    raise ValidationError(error_msg)
                
                cur.execute("""
                    UPDATE users SET full_name=%s, email=%s, role=%s, password=%s
                    WHERE id=%s
                """, (
                    request.form.get('full_name'),
                    request.form.get('email', '').strip().lower(),
                    role,
                    generate_password_hash(new_password),
                    id
                ))
            else:
                cur.execute("""
                    UPDATE users SET full_name=%s, email=%s, role=%s WHERE id=%s
                """, (
                    request.form.get('full_name'),
                    request.form.get('email', '').strip().lower(),
                    role,
                    id
                ))

            app.logger.info(f"User updated: {id}")
            flash("User updated.")
            return redirect(url_for('manage_users'))

        cur.execute("SELECT * FROM users WHERE id = %s", (id,))
        user = cur.fetchone()

    if not user:
        flash("User not found.")
        return redirect(url_for('manage_users'))

    return render_template('edit_user.html', user=user)


@app.route('/admin/delete_user/<int:id>', methods=['POST'])
@admin_required
@handle_errors
def delete_user(id: int):
    """Delete a user account."""
    with db_cursor(dict_cursor=True) as (cur, conn):
        cur.execute("SELECT username FROM users WHERE id = %s", (id,))
        user = cur.fetchone()

        if user and user['username'] == 'admin':
            flash("Cannot delete the main administrator account.")
        else:
            cur.execute("DELETE FROM users WHERE id = %s", (id,))
            app.logger.info(f"User deleted: {id}")
            flash("User deleted.")

    return redirect(url_for('manage_users'))


@app.route('/admin/logs')
@admin_required
@handle_errors
def admin_logs():
    """Display login logs."""
    with db_cursor(dict_cursor=True) as (cur, conn):
        cur.execute("SELECT * FROM login_logs ORDER BY login_time DESC LIMIT 100")
        logs = cur.fetchall()

    return render_template('login_logs.html', logs=logs)


@app.route('/admin/backup', methods=['GET'])
@admin_required
@handle_errors
def backup_database():
    """Export entire database as JSON backup."""
    with db_cursor() as (cur, conn):
        # Get all table names
        cur.execute("""
            SELECT table_name FROM information_schema.tables 
            WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
        """)
        tables = [row[0] for row in cur.fetchall()]
        
        backup_data = {}
        for table in tables:
            cur.execute(f"SELECT * FROM {table}")
            columns = [desc[0] for desc in cur.description]
            rows = cur.fetchall()
            backup_data[table] = {
                'columns': columns,
                'rows': rows
            }
        
        backup_json = json.dumps(backup_data, default=str, indent=2)
        
        output = io.BytesIO()
        output.write(backup_json.encode('utf-8'))
        output.seek(0)
        
        app.logger.info("Database backup completed")
        return send_file(
            output,
            mimetype='application/json',
            as_attachment=True,
            download_name=f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )

# ============================================================================
# Application Entry Point
# ============================================================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
