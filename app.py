import os
import io
import csv
import base64
import traceback
import secrets
import string
import qrcode
import psycopg2
import psycopg2.extras
import psycopg2.pool
import pandas as pd
import logging
from logging.handlers import RotatingFileHandler
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, Response, jsonify
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

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
file_handler = logging.handlers.RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Asset Tracker startup')

# In-memory rate limiting for login attempts
login_attempts = {}


def get_db_connection():
    url = DATABASE_URL
    if url and url.startswith('postgres://'):
        url = url.replace('postgres://', 'postgresql://', 1)
    try:
        return connection_pool.getconn()
    except:
        return psycopg2.connect(url)


def release_db_connection(conn):
    try:
        connection_pool.putconn(conn)
    except:
        conn.close()


def is_admin():
    return session.get('role') == 'Admin'


def validate_password_complexity(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"
    return True, "Password is valid"


def generate_temp_password():
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(10))


def check_rate_limit(email):
    now = datetime.now()
    if email in login_attempts:
        attempts = login_attempts[email]
        attempts = [t for t in attempts if (now - t).total_seconds() < 900]
        login_attempts[email] = attempts
        if len(attempts) >= 5:
            return False, "Too many login attempts. Please try again in 15 minutes."
    else:
        login_attempts[email] = []
    return True, None


def log_activity(user_label, action, asset_serial=None):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO activity_logs (user_email, action, asset_serial) VALUES (%s,%s,%s)",
            (user_label, action, asset_serial)
        )
        conn.commit()
        cur.close()
        release_db_connection(conn)
    except Exception as e:
        app.logger.error(f"ACTIVITY LOG ERROR: {e}")


def log_access(email, action):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO access_logs (user_email, action) VALUES (%s,%s)",
            (email, action)
        )
        conn.commit()
        cur.close()
        release_db_connection(conn)
    except Exception as e:
        app.logger.error(f"ACCESS LOG ERROR: {e}")


def ensure_bootstrap_admin():
    email = os.environ.get('BOOTSTRAP_ADMIN_EMAIL', 'admin@jtdi.gov.my').strip().lower()
    password = 'Admin123'
    username = os.environ.get('BOOTSTRAP_ADMIN_USERNAME', 'admin')
    full_name = os.environ.get('BOOTSTRAP_ADMIN_NAME', 'System Administrator')

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cur.execute(
        "SELECT id FROM users WHERE username = %s OR email = %s",
        (username, email)
    )
    row = cur.fetchone()
    if row:
        cur.execute("""
            UPDATE users
            SET full_name = %s, email = %s, password = %s, role = 'Admin', first_login = FALSE
            WHERE id = %s
        """, (full_name, email, password, row['id']))
    else:
        cur.execute("""
            INSERT INTO users (full_name, username, email, password, role, first_login)
            VALUES (%s, %s, %s, %s, 'Admin', FALSE)
        """, (full_name, username, email, password))
    conn.commit()
    cur.close()
    conn.close()


def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    try:
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

        cur.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS description TEXT;")
        cur.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS scan_count INTEGER DEFAULT 0;")
        cur.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN DEFAULT FALSE;")
        cur.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS assigned_to TEXT;")
        cur.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS checkout_date TIMESTAMP;")
        cur.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS checkout_by TEXT;")
        cur.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS owner_name TEXT;")

        cur.execute("CREATE INDEX IF NOT EXISTS idx_assets_serial ON assets(serial_number);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_assets_tracking ON assets(tracking_number);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_assets_location ON assets(location);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_assets_deleted ON assets(is_deleted);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_assets_assigned ON assets(assigned_to);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_activity_created ON activity_logs(created_at);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_login_time ON login_logs(login_time);")

        cur.execute('''CREATE TABLE IF NOT EXISTS maintenance_logs (
            id SERIAL PRIMARY KEY,
            asset_id INTEGER REFERENCES assets(id),
            action_type TEXT,
            comment TEXT,
            updated_by TEXT,
            log_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );''')

        cur.execute('''CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            full_name TEXT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'User',
            first_login BOOLEAN DEFAULT TRUE
        );''')
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name TEXT;")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS first_login BOOLEAN DEFAULT TRUE;")

        cur.execute('''CREATE TABLE IF NOT EXISTS login_logs (
            id SERIAL PRIMARY KEY,
            full_name TEXT,
            email TEXT,
            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );''')

        cur.execute('''CREATE TABLE IF NOT EXISTS activity_logs (
            id SERIAL PRIMARY KEY,
            user_email TEXT,
            action TEXT,
            asset_serial TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );''')

        cur.execute('''CREATE TABLE IF NOT EXISTS access_logs (
            id SERIAL PRIMARY KEY,
            user_email TEXT,
            action TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );''')

        conn.commit()
    except Exception as e:
        conn.rollback()
        app.logger.error(f"INIT DB ERROR: {e}")
        raise
    finally:
        cur.close()
        release_db_connection(conn)


def safe_startup():
    if not DATABASE_URL:
        app.logger.warning("DATABASE_URL is not set. DB init and bootstrap skipped.")
        return
    try:
        init_db()
        ensure_bootstrap_admin()
        app.logger.info(f"Startup OK.")
    except Exception as e:
        app.logger.error(f"STARTUP ERROR: {e}")
        traceback.print_exc()


safe_startup()


@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        user_role = session.get('role')
        user_email = session.get('email')
        
        if user_role == 'Admin':
            cur.execute("SELECT COUNT(*) FROM assets WHERE is_deleted = FALSE")
            total = cur.fetchone()['count']
            cur.execute("SELECT COUNT(*) FROM assets WHERE status = 'Working' AND is_deleted = FALSE")
            working = cur.fetchone()['count']
            cur.execute("SELECT COUNT(*) FROM assets WHERE status = 'Maintenance' AND is_deleted = FALSE")
            maint = cur.fetchone()['count']
            cur.execute("SELECT COUNT(*) FROM assets WHERE status = 'Faulty' AND is_deleted = FALSE")
            faulty = cur.fetchone()['count']
            cur.execute("SELECT COUNT(*) FROM assets WHERE assigned_to IS NOT NULL AND is_deleted = FALSE")
            assigned = cur.fetchone()['count']
            
            cur.execute("SELECT asset_type, COUNT(*) as count FROM assets WHERE is_deleted = FALSE AND asset_type IS NOT NULL GROUP BY asset_type")
            by_type = cur.fetchall()
            cur.execute("SELECT location, COUNT(*) as count FROM assets WHERE is_deleted = FALSE AND location IS NOT NULL GROUP BY location")
            by_location = cur.fetchall()
            cur.execute("SELECT status, COUNT(*) as count FROM assets WHERE is_deleted = FALSE GROUP BY status")
            by_status = cur.fetchall()
        else:
            cur.execute("""
                SELECT COUNT(*) FROM assets 
                WHERE is_deleted = FALSE AND (assigned_to = %s OR assigned_to = %s)
            """, (user_email, session.get('full_name')))
            total = cur.fetchone()['count']
            
            cur.execute("""
                SELECT COUNT(*) FROM assets 
                WHERE status = 'Working' AND is_deleted = FALSE AND (assigned_to = %s OR assigned_to = %s)
            """, (user_email, session.get('full_name')))
            working = cur.fetchone()['count']
            
            cur.execute("""
                SELECT COUNT(*) FROM assets 
                WHERE status = 'Maintenance' AND is_deleted = FALSE AND (assigned_to = %s OR assigned_to = %s)
            """, (user_email, session.get('full_name')))
            maint = cur.fetchone()['count']
            
            cur.execute("""
                SELECT COUNT(*) FROM assets 
                WHERE status = 'Faulty' AND is_deleted = FALSE AND (assigned_to = %s OR assigned_to = %s)
            """, (user_email, session.get('full_name')))
            faulty = cur.fetchone()['count']
            
            assigned = total
            
            cur.execute("""
                SELECT asset_type, COUNT(*) as count FROM assets 
                WHERE is_deleted = FALSE AND asset_type IS NOT NULL 
                AND (assigned_to = %s OR assigned_to = %s)
                GROUP BY asset_type
            """, (user_email, session.get('full_name')))
            by_type = cur.fetchall()
            
            cur.execute("""
                SELECT location, COUNT(*) as count FROM assets 
                WHERE is_deleted = FALSE AND location IS NOT NULL 
                AND (assigned_to = %s OR assigned_to = %s)
                GROUP BY location
            """, (user_email, session.get('full_name')))
            by_location = cur.fetchall()
            
            cur.execute("""
                SELECT status, COUNT(*) as count FROM assets 
                WHERE is_deleted = FALSE 
                AND (assigned_to = %s OR assigned_to = %s)
                GROUP BY status
            """, (user_email, session.get('full_name')))
            by_status = cur.fetchall()
        
        cur.execute("SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT 10")
        recent_activity = cur.fetchall()
        
        cur.close()
        release_db_connection(conn)

        type_labels = [item['asset_type'] or 'Unknown' for item in by_type]
        type_data = [item['count'] for item in by_type]
        location_labels = [item['location'] or 'Unknown' for item in by_location]
        location_data = [item['count'] for item in by_location]
        status_labels = [item['status'] or 'Unknown' for item in by_status]
        status_data = [item['count'] for item in by_status]

        return render_template('dashboard.html', 
                             total=total, working=working, maint=maint, faulty=faulty, 
                             assigned=assigned,
                             recent_activity=recent_activity,
                             type_labels=type_labels, type_data=type_data,
                             location_labels=location_labels, location_data=location_data,
                             status_labels=status_labels, status_data=status_data)
    except Exception as e:
        app.logger.error(f"Dashboard error: {e}")
        flash("An error occurred loading the dashboard.")
        return redirect(url_for('index'))


@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))

    try:
        s = request.args.get('search', '').strip()
        c = request.args.get('category', '').strip()
        sort = request.args.get('sort', 'id')
        order = request.args.get('order', 'desc')
        page = request.args.get('page', 1, type=int)
        per_page = 20

        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        query = "SELECT * FROM assets WHERE is_deleted = FALSE"
        count_query = "SELECT COUNT(*) FROM assets WHERE is_deleted = FALSE"
        params = []
        
        if session.get('role') != 'Admin':
            query += " AND (assigned_to = %s OR assigned_to = %s)"
            count_query += " AND (assigned_to = %s OR assigned_to = %s)"
            params.append(session.get('email'))
            params.append(session.get('full_name'))
            
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

        cur.execute(count_query, tuple(params))
        total = cur.fetchone()['count']
        
        valid_sorts = ['id', 'tracking_number', 'cpu_name', 'serial_number', 'status', 'location', 'asset_type']
        if sort not in valid_sorts:
            sort = 'id'
        order_dir = 'DESC' if order.lower() == 'desc' else 'ASC'
        query += f" ORDER BY {sort} {order_dir}"
        
        offset = (page - 1) * per_page
        query += f" LIMIT {per_page} OFFSET {offset}"
        
        cur.execute(query, tuple(params))
        data = cur.fetchall()

        users = []
        if session.get('role') == 'Admin':
            cur.execute("SELECT email, full_name, username FROM users ORDER BY email")
            users_list = cur.fetchall()
            users = [{'email': u['email'], 'full_name': u['full_name'], 'username': u['username']} for u in users_list]

        stats = {
            'total': total,
            'working': len([r for r in data if r['status'] == 'Working']),
            'maint': len([r for r in data if r['status'] == 'Maintenance']),
            'faulty': len([r for r in data if r['status'] == 'Faulty'])
        }
        
        total_pages = (total + per_page - 1) // per_page
        cur.close()
        release_db_connection(conn)

        return render_template('assets.html', data=data, **stats, s_query=s, c_filter=c,
                             sort=sort, order=order, page=page, total_pages=total_pages, 
                             per_page=per_page, users=users)
    except Exception as e:
        app.logger.error(f"Index error: {e}")
        flash("An error occurred loading assets.")
        return redirect(url_for('dashboard'))


@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit_asset(id):
    if 'user' not in session:
        return redirect(url_for('login'))

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        if session.get('role') != 'Admin':
            cur.execute("SELECT assigned_to FROM assets WHERE id = %s", (id,))
            asset_check = cur.fetchone()
            if not asset_check or (asset_check['assigned_to'] != session.get('email') and asset_check['assigned_to'] != session.get('full_name')):
                flash("You don't have permission to edit this asset.")
                cur.close()
                release_db_connection(conn)
                return redirect(url_for('index'))

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
                    description=%s,
                    owner_name=%s
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
                request.form.get('owner_name'),
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
            conn.commit()
            cur.close()
            conn.close()

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
        cur.close()
        release_db_connection(conn)

        if not asset:
            flash("Asset not found.")
            return redirect(url_for('index'))

        return render_template('edit.html', asset=asset)
    except Exception as e:
        app.logger.error(f"Edit asset error: {e}")
        flash("An error occurred updating the asset.")
        return redirect(url_for('index'))


@app.route('/view/<int:id>')
def view_asset(id):
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("SELECT * FROM assets WHERE id = %s", (id,))
        asset = cur.fetchone()
        if not asset:
            cur.close()
            conn.close()
            return "Not Found", 404
        
        if session.get('role') != 'Admin' and asset['assigned_to'] != session.get('email') and asset['assigned_to'] != session.get('full_name'):
            flash("You don't have permission to view this asset.")
            cur.close()
            release_db_connection(conn)
            return redirect(url_for('index'))

        cur.execute(
            "UPDATE assets SET scan_count = COALESCE(scan_count, 0) + 1 WHERE id = %s",
            (id,)
        )
        cur.execute(
            "SELECT * FROM maintenance_logs WHERE asset_id = %s ORDER BY log_date DESC",
            (id,)
        )
        logs = cur.fetchall()
        conn.commit()
        cur.close()
        release_db_connection(conn)

        return render_template('view.html', asset=asset, logs=logs)
    except Exception as e:
        app.logger.error(f"View asset error: {e}")
        flash("An error occurred loading the asset.")
        return redirect(url_for('index'))


@app.route('/asset/<int:id>')
def legacy_asset_view(id):
    return redirect(url_for('view_asset', id=id))


@app.route('/qr/<int:id>')
def qr_code(id):
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("SELECT * FROM assets WHERE id = %s", (id,))
        asset = cur.fetchone()
        cur.close()
        release_db_connection(conn)

        if not asset:
            flash("Asset not found.")
            return redirect(url_for('index'))

        qr_url = url_for('view_asset', id=id, _external=True)
        img = qrcode.make(qr_url)
        buf = io.BytesIO()
        img.save(buf)
        qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')

        return render_template('qr_display.html', qr_code=qr_b64, asset=asset)
    except Exception as e:
        app.logger.error(f"QR code error: {e}")
        flash("An error occurred generating the QR code.")
        return redirect(url_for('index'))


@app.route('/assign/<int:id>', methods=['POST'])
def assign_asset(id):
    if 'user' not in session or session.get('role') != 'Admin':
        flash("Only admins can assign assets.")
        return redirect(url_for('login'))

    try:
        assigned_to_email = request.form.get('assigned_to_email', '').strip()
        if not assigned_to_email:
            flash("Please select a user to assign this asset.")
            return redirect(url_for('index'))

        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cur.execute("SELECT email, full_name, username FROM users WHERE email = %s", (assigned_to_email,))
        user = cur.fetchone()
        
        if not user:
            flash("Selected user not found.")
            cur.close()
            release_db_connection(conn)
            return redirect(url_for('index'))
        
        assigned_to_display = user['full_name'] if user['full_name'] else user['username']
        
        cur.execute("SELECT serial_number FROM assets WHERE id = %s", (id,))
        row = cur.fetchone()
        
        cur.execute("""
            UPDATE assets SET 
                assigned_to = %s,
                checkout_date = %s,
                checkout_by = %s,
                status = 'Assigned'
            WHERE id = %s
        """, (assigned_to_display, datetime.now(), session.get('full_name'), id))
        
        conn.commit()
        cur.close()
        release_db_connection(conn)

        if row:
            log_activity(
                session.get('email') or session.get('full_name'),
                f"ASSET ASSIGNED TO {assigned_to_display}",
                row['serial_number']
            )
            app.logger.info(f"Asset assigned: {id} to {assigned_to_display}")
        flash(f"Asset assigned to {assigned_to_display}.")
        return redirect(url_for('index'))
    except Exception as e:
        app.logger.error(f"Assign asset error: {e}")
        flash("An error occurred assigning the asset.")
        return redirect(url_for('index'))


@app.route('/return/<int:id>', methods=['POST'])
def return_asset(id):
    if 'user' not in session:
        return redirect(url_for('login'))

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cur.execute("SELECT serial_number, assigned_to FROM assets WHERE id = %s", (id,))
        row = cur.fetchone()
        
        if session.get('role') != 'Admin' and row and row['assigned_to'] != session.get('email') and row['assigned_to'] != session.get('full_name'):
            flash("You can only return assets assigned to you.")
            cur.close()
            release_db_connection(conn)
            return redirect(url_for('index'))
        
        cur.execute("""
            UPDATE assets SET 
                assigned_to = NULL,
                checkout_date = NULL,
                checkout_by = NULL,
                status = 'Returned'
            WHERE id = %s
        """, (id,))
        
        conn.commit()
        cur.close()
        release_db_connection(conn)

        if row:
            log_activity(
                session.get('email') or session.get('full_name'),
                f"ASSET RETURNED",
                row['serial_number']
            )
            app.logger.info(f"Asset returned: {id}")
        flash("Asset returned successfully.")
        return redirect(url_for('index'))
    except Exception as e:
        app.logger.error(f"Return asset error: {e}")
        flash("An error occurred returning the asset.")
        return redirect(url_for('index'))


@app.route('/delete/<int:id>', methods=['POST'])
def delete_asset(id):
    if 'user' not in session:
        return redirect(url_for('login'))

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("SELECT serial_number FROM assets WHERE id = %s", (id,))
        row = cur.fetchone()
        cur.execute("UPDATE assets SET is_deleted = TRUE WHERE id = %s", (id,))
        conn.commit()
        cur.close()
        release_db_connection(conn)

        if row:
            log_activity(
                session.get('email') or session.get('full_name'),
                "ASSET ARCHIVED",
                row['serial_number']
            )
            app.logger.info(f"Asset archived: {id}")
        flash("Asset archived.")
        return redirect(url_for('index'))
    except Exception as e:
        app.logger.error(f"Delete asset error: {e}")
        flash("An error occurred archiving the asset.")
        return redirect(url_for('index'))


@app.route('/add', methods=['GET', 'POST'])
def add_asset():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            tn = (request.form.get('tracking_number') or '').strip()
            if not tn:
                tn = f"JTDI-{datetime.now().strftime('%y%m%H%M%S')}"

            cur.execute("""
                INSERT INTO assets (
                    asset_type, tracking_number, cpu_name, serial_number,
                    ram_size, storage_type, status, location, description, is_deleted, owner_name
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s, FALSE, %s)
            """, (
                request.form.get('asset_type'),
                tn,
                request.form.get('cpu_name'),
                request.form.get('serial_number'),
                request.form.get('ram_size'),
                request.form.get('storage_type'),
                request.form.get('status'),
                request.form.get('location'),
                request.form.get('description'),
                request.form.get('owner_name')
            ))
            conn.commit()
            cur.close()
            conn.close()

            log_activity(
                session.get('email') or session.get('full_name'),
                "ASSET REGISTERED",
                request.form.get('serial_number')
            )
            app.logger.info(f"Asset added: {request.form.get('serial_number')}")
            flash("Asset added successfully!")
            return redirect(url_for('index'))
        except Exception as e:
            app.logger.error(f"Add asset error: {e}")
            flash("Error: Serial number may already exist.")

    return render_template('add.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        session.clear()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        allowed, error_msg = check_rate_limit(email)
        if not allowed:
            flash(error_msg)
            return render_template('login.html')

        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cur.fetchone()

            if user and user['password'] == password:
                if email in login_attempts:
                    del login_attempts[email]

                if user.get('first_login', True):
                    session.permanent = True
                    session.update({
                        'user': user['username'],
                        'role': user['role'],
                        'full_name': user['full_name'] or user['username'],
                        'email': user['email']
                    })
                    cur.execute("INSERT INTO login_logs (full_name, email) VALUES (%s, %s)",
                               (user['full_name'] or user['username'], user['email']))
                    conn.commit()
                    cur.close()
                    conn.close()
                    log_access(user['email'], "LOGIN")
                    return redirect(url_for('change_password'))

                session.permanent = True
                session.update({
                    'user': user['username'],
                    'role': user['role'],
                    'full_name': user['full_name'] or user['username'],
                    'email': user['email']
                })
                cur.execute("INSERT INTO login_logs (full_name, email) VALUES (%s, %s)",
                           (user['full_name'] or user['username'], user['email']))
                conn.commit()
                cur.close()
                conn.close()
                log_access(user['email'], "LOGIN")
                app.logger.info(f"User logged in: {email}")
                return redirect(url_for('dashboard'))
            else:
                if email not in login_attempts:
                    login_attempts[email] = []
                login_attempts[email].append(datetime.now())
                app.logger.warning(f"Failed login attempt for: {email}")

            cur.close()
            conn.close()
            flash("Invalid email or password.")
        except Exception as e:
            app.logger.error(f"Login error: {e}")
            flash("An error occurred during login. Please try again.")

    return render_template('login.html')


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if new_password != confirm_password:
            flash("New passwords do not match.")
            return render_template('change_password.html')
        
        is_valid, msg = validate_password_complexity(new_password)
        if not is_valid:
            flash(msg)
            return render_template('change_password.html')
        
        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            cur.execute("SELECT password FROM users WHERE email = %s", (session.get('email'),))
            user = cur.fetchone()
            
            if user and user['password'] == current_password:
                cur.execute("UPDATE users SET password = %s, first_login = FALSE WHERE email = %s", 
                           (new_password, session.get('email')))
                conn.commit()
                flash("Password changed successfully! Please login again.")
                session.clear()
                cur.close()
                release_db_connection(conn)
                return redirect(url_for('login'))
            else:
                flash("Current password is incorrect.")
            
            cur.close()
            release_db_connection(conn)
        except Exception as e:
            app.logger.error(f"Password change error: {e}")
            flash("An error occurred changing password.")
        
        return render_template('change_password.html')
    
    return render_template('change_password.html')


@app.route('/logout')
def logout():
    if session.get('email'):
        log_access(session['email'], "LOGOUT")
    session.clear()
    return redirect(url_for('login'))


@app.route('/activity')
def activity():
    if 'user' not in session:
        return redirect(url_for('login'))

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT 200")
        logs = cur.fetchall()
        cur.close()
        release_db_connection(conn)

        return render_template('activity.html', logs=logs)
    except Exception as e:
        app.logger.error(f"Activity error: {e}")
        flash("An error occurred loading activity logs.")
        return redirect(url_for('dashboard'))


@app.route('/export')
def export_csv():
    if 'user' not in session:
        return redirect(url_for('login'))

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        query = "SELECT * FROM assets WHERE is_deleted = FALSE"
        params = []
        
        if session.get('role') != 'Admin':
            query += " AND (assigned_to = %s OR assigned_to = %s)"
            params = [session.get('email'), session.get('full_name')]
            
        query += " ORDER BY id DESC"
        cur.execute(query, params)
        rows = cur.fetchall()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([d[0] for d in cur.description])
        writer.writerows(rows)
        output.seek(0)

        cur.close()
        release_db_connection(conn)

        app.logger.info("CSV export completed")
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment;filename=assets.csv"}
        )
    except Exception as e:
        app.logger.error(f"CSV export error: {e}")
        flash("An error occurred during CSV export.")
        return redirect(url_for('index'))


@app.route('/export/excel')
def export_excel():
    if 'user' not in session:
        return redirect(url_for('login'))

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        query = "SELECT * FROM assets WHERE is_deleted = FALSE"
        params = []
        
        if session.get('role') != 'Admin':
            query += " AND (assigned_to = %s OR assigned_to = %s)"
            params = [session.get('email'), session.get('full_name')]
            
        query += " ORDER BY id DESC"
        cur.execute(query, params)
        column_names = [desc[0] for desc in cur.description]
        rows = cur.fetchall()
        
        cur.close()
        release_db_connection(conn)

        data = []
        for row in rows:
            data.append(dict(zip(column_names, row)))
        
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
    except Exception as e:
        app.logger.error(f"Excel export error: {e}")
        flash(f"Error exporting to Excel: {str(e)}")
        return redirect(url_for('index'))


@app.route('/export/analytics_report')
def export_analytics_report():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        user_role = session.get('role')
        user_email = session.get('email')
        
        if user_role == 'Admin':
            cur.execute("SELECT asset_type, COUNT(*) as count FROM assets WHERE is_deleted = FALSE AND asset_type IS NOT NULL GROUP BY asset_type")
            by_type = cur.fetchall()
            cur.execute("SELECT location, COUNT(*) as count FROM assets WHERE is_deleted = FALSE AND location IS NOT NULL GROUP BY location")
            by_location = cur.fetchall()
            cur.execute("SELECT status, COUNT(*) as count FROM assets WHERE is_deleted = FALSE GROUP BY status")
            by_status = cur.fetchall()
            cur.execute("SELECT COUNT(*) as total FROM assets WHERE is_deleted = FALSE")
            total_assets = cur.fetchone()['total']
        else:
            cur.execute("""
                SELECT asset_type, COUNT(*) as count FROM assets 
                WHERE is_deleted = FALSE AND (assigned_to = %s OR assigned_to = %s) AND asset_type IS NOT NULL 
                GROUP BY asset_type
            """, (user_email, session.get('full_name')))
            by_type = cur.fetchall()
            cur.execute("""
                SELECT location, COUNT(*) as count FROM assets 
                WHERE is_deleted = FALSE AND (assigned_to = %s OR assigned_to = %s) AND location IS NOT NULL 
                GROUP BY location
            """, (user_email, session.get('full_name')))
            by_location = cur.fetchall()
            cur.execute("""
                SELECT status, COUNT(*) as count FROM assets 
                WHERE is_deleted = FALSE AND (assigned_to = %s OR assigned_to = %s) 
                GROUP BY status
            """, (user_email, session.get('full_name')))
            by_status = cur.fetchall()
            cur.execute("""
                SELECT COUNT(*) as total FROM assets 
                WHERE is_deleted = FALSE AND (assigned_to = %s OR assigned_to = %s)
            """, (user_email, session.get('full_name')))
            total_assets = cur.fetchone()['total']
        
        cur.close()
        release_db_connection(conn)
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Asset Analytics Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ text-align: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 2px solid #1a2a6c; }}
                .report-title {{ color: #1a2a6c; font-size: 24px; }}
                .report-date {{ color: #666; font-size: 14px; }}
                .summary {{ background: #f5f5f5; padding: 15px; border-radius: 8px; margin-bottom: 30px; }}
                .summary h3 {{ margin-top: 0; color: #1a2a6c; }}
                .summary-number {{ font-size: 36px; font-weight: bold; color: #1a2a6c; }}
                .section {{ margin-bottom: 30px; }}
                .section-title {{ background: #1a2a6c; color: white; padding: 10px; border-radius: 5px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
                th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background: #f0f0f0; }}
                .footer {{ text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #666; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1 class="report-title">JTDI Asset Tracker - Analytics Report</h1>
                <p class="report-date">Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>User: {session.get('full_name')} ({session.get('role')})</p>
            </div>
            
            <div class="summary">
                <h3>Summary</h3>
                <div class="summary-number">{total_assets}</div>
                <p>Total Assets in System</p>
            </div>
            
            <div class="section">
                <h3 class="section-title">Assets by Type</h3>
                <table>
                    <tr><th>Asset Type</th><th>Count</th></tr>
        """
        
        for item in by_type:
            html_content += f"<tr><td>{item['asset_type'] or 'Unknown'}</td><td>{item['count']}</td></tr>"
        
        html_content += """
                </table>
            </div>
            
            <div class="section">
                <h3 class="section-title">Assets by Department</h3>
                <table>
                    <tr><th>Department</th><th>Count</th></tr>
        """
        
        for item in by_location:
            html_content += f"<tr><td>{item['location'] or 'Unknown'}</td><td>{item['count']}</td></tr>"
        
        html_content += """
                </table>
            </div>
            
            <div class="section">
                <h3 class="section-title">Assets by Status</h3>
                <table>
                    <tr><th>Status</th><th>Count</th></tr>
        """
        
        for item in by_status:
            html_content += f"<tr><td>{item['status'] or 'Unknown'}</td><td>{item['count']}</td></tr>"
        
        html_content += f"""
                </table>
            </div>
            
            <div class="footer">
                <p>JTDI Asset Tracker System - Confidential Report</p>
                <p>This report was generated automatically. For questions, contact system administrator.</p>
            </div>
        </body>
        </html>
        """
        
        output = io.BytesIO()
        output.write(html_content.encode('utf-8'))
        output.seek(0)
        
        return send_file(
            output,
            mimetype='text/html',
            as_attachment=True,
            download_name=f"analytics_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        )
    except Exception as e:
        app.logger.error(f"Analytics report error: {e}")
        flash("An error occurred generating the report.")
        return redirect(url_for('dashboard'))


@app.route('/export/repair_request/<int:id>')
def export_repair_request(id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("SELECT * FROM assets WHERE id = %s", (id,))
        asset = cur.fetchone()
        cur.close()
        release_db_connection(conn)
        
        if not asset:
            flash("Asset not found.")
            return redirect(url_for('index'))
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Repair Request Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ text-align: center; margin-bottom: 30px; border-bottom: 2px solid #dc3545; padding-bottom: 20px; }}
                .title {{ color: #dc3545; font-size: 24px; }}
                .asset-info {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
                .info-row {{ margin-bottom: 10px; }}
                .info-label {{ font-weight: bold; width: 150px; display: inline-block; }}
                .section {{ margin-bottom: 30px; }}
                .section-title {{ background: #dc3545; color: white; padding: 10px; border-radius: 5px; }}
                .parts-table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
                .parts-table th, .parts-table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                .parts-table th {{ background: #f0f0f0; }}
                .signature {{ margin-top: 40px; }}
                .signature-line {{ margin-top: 30px; display: flex; justify-content: space-between; }}
                .footer {{ margin-top: 40px; text-align: center; font-size: 12px; color: #666; }}
                @media print {{
                    body {{ margin: 0; }}
                    .no-print {{ display: none; }}
                }}
            </style>
        </head>
        <body>
            <div class="no-print" style="text-align: right; margin-bottom: 20px;">
                <button onclick="window.print()" style="padding: 10px 20px; background: #1a2a6c; color: white; border: none; border-radius: 5px; cursor: pointer;">
                    Print / Save as PDF
                </button>
            </div>
            
            <div class="header">
                <h1 class="title">REPAIR REQUEST REPORT</h1>
                <p>JTDI Asset Tracker System</p>
                <p>Date: {datetime.now().strftime('%Y-%m-%d')}</p>
            </div>
            
            <div class="asset-info">
                <h3>Asset Information</h3>
                <div class="info-row"><span class="info-label">Asset ID:</span> {asset['id']}</div>
                <div class="info-row"><span class="info-label">Tracking Number:</span> {asset['tracking_number']}</div>
                <div class="info-row"><span class="info-label">Asset Name/Model:</span> {asset['cpu_name'] or 'N/A'}</div>
                <div class="info-row"><span class="info-label">Serial Number:</span> {asset['serial_number']}</div>
                <div class="info-row"><span class="info-label">Asset Type:</span> {asset['asset_type'] or 'N/A'}</div>
                <div class="info-row"><span class="info-label">Department:</span> {asset['location'] or 'N/A'}</div>
                <div class="info-row"><span class="info-label">Repair Status:</span> <strong style="color: #dc3545;">Waiting for Repair</strong></div>
            </div>
            
            <div class="section">
                <h3 class="section-title">Required Parts / Components</h3>
                <table class="parts-table">
                    <thead>
                        <tr><th>No.</th><th>Part Name</th><th>Quantity</th><th>Estimated Cost (RM)</th></tr>
                    </thead>
                    <tbody>
                        <tr><td>1</td><td style="height: 40px;"></td><td></td><td></td></tr>
                        <tr><td>2</td><td style="height: 40px;"></td><td></td><td></td></tr>
                        <tr><td>3</td><td style="height: 40px;"></td><td></td><td></td></tr>
                        <tr><td>4</td><td style="height: 40px;"></td><td></td><td></td></tr>
                        <tr><td>5</td><td style="height: 40px;"></td><td></td><td></td></tr>
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <h3 class="section-title">Remarks / Notes</h3>
                <div style="height: 100px; border: 1px solid #ddd; padding: 10px; margin-top: 10px;"></div>
            </div>
            
            <div class="signature">
                <div class="signature-line">
                    <div style="text-align: center;">
                        <div style="height: 60px;"></div>
                        <div style="border-top: 1px solid #000; width: 200px;"></div>
                        <p>Requested By (Technician)</p>
                    </div>
                    <div style="text-align: center;">
                        <div style="height: 60px;"></div>
                        <div style="border-top: 1px solid #000; width: 200px;"></div>
                        <p>Approved By (Supervisor)</p>
                    </div>
                    <div style="text-align: center;">
                        <div style="height: 60px;"></div>
                        <div style="border-top: 1px solid #000; width: 200px;"></div>
                        <p>Received By (Store)</p>
                    </div>
                </div>
            </div>
            
            <div class="footer">
                <p>This is a system-generated repair request. Please complete all required sections.</p>
            </div>
        </body>
        </html>
        """
        
        output = io.BytesIO()
        output.write(html_content.encode('utf-8'))
        output.seek(0)
        
        return send_file(
            output,
            mimetype='text/html',
            as_attachment=True,
            download_name=f"repair_request_{asset['tracking_number']}_{datetime.now().strftime('%Y%m%d')}.html"
        )
    except Exception as e:
        app.logger.error(f"Repair request error: {e}")
        flash("An error occurred generating the repair request.")
        return redirect(url_for('index'))


@app.route('/completed_assets')
def completed_assets():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cur.execute("""
            SELECT a.*, m.comment as last_maintenance, m.log_date as last_maintenance_date
            FROM assets a
            LEFT JOIN maintenance_logs m ON a.id = m.asset_id
            WHERE a.is_deleted = FALSE 
            AND (a.assigned_to = %s OR a.assigned_to = %s)
            AND a.status IN ('Returned', 'Completed', 'Cannot Be Repaired')
            ORDER BY a.checkout_date DESC
        """, (session.get('email'), session.get('full_name')))
        
        completed_assets = cur.fetchall()
        cur.close()
        release_db_connection(conn)
        
        return render_template('completed_assets.html', assets=completed_assets)
    except Exception as e:
        app.logger.error(f"Completed assets error: {e}")
        flash("An error occurred loading completed assets.")
        return redirect(url_for('dashboard'))


@app.route('/admin')
def admin_dashboard():
    if not is_admin():
        return redirect(url_for('login'))

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("SELECT * FROM users ORDER BY id DESC")
        users = cur.fetchall()
        cur.execute("SELECT * FROM access_logs ORDER BY created_at DESC LIMIT 25")
        access_logs = cur.fetchall()
        cur.execute("SELECT * FROM login_logs ORDER BY login_time DESC LIMIT 100")
        login_logs = cur.fetchall()

        cur.close()
        release_db_connection(conn)

        return render_template('admin.html', users=users, access_logs=access_logs, login_logs=login_logs)
    except Exception as e:
        app.logger.error(f"Admin dashboard error: {e}")
        flash("An error occurred loading the admin dashboard.")
        return redirect(url_for('dashboard'))


@app.route('/admin/users', methods=['GET', 'POST'])
def manage_users():
    if not is_admin():
        return redirect(url_for('login'))

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        if request.method == 'POST':
            role = request.form.get('role', 'User')
            if role not in ('User', 'Admin'):
                role = 'User'
            
            email = request.form.get('email', '').strip().lower()
            username = email.split('@')[0].replace('.', '_').replace('-', '_')
            full_name = request.form.get('full_name') or username
            
            temp_password = generate_temp_password()
            
            try:
                cur.execute("""
                    INSERT INTO users (full_name, username, email, password, role, first_login)
                    VALUES (%s, %s, %s, %s, %s, TRUE)
                """, (
                    full_name,
                    username,
                    email,
                    temp_password,
                    role
                ))
                conn.commit()
                app.logger.info(f"User created: {email}")
                flash(f"User created successfully! Temporary password: {temp_password}")
                app.logger.info(f"Temporary password for {email}: {temp_password}")
            except Exception as e:
                conn.rollback()
                app.logger.error(f"User creation error: {e}")
                flash("Error: Email already exists.")

        cur.execute("SELECT * FROM users ORDER BY id DESC")
        users = cur.fetchall()
        cur.close()
        release_db_connection(conn)

        return render_template('manage_user.html', users=users)
    except Exception as e:
        app.logger.error(f"Manage users error: {e}")
        flash("An error occurred. Please try again.")
        return redirect(url_for('admin_dashboard'))


@app.route('/admin/edit_user/<int:id>', methods=['GET', 'POST'])
def edit_user(id):
    if not is_admin():
        return redirect(url_for('login'))

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        if request.method == 'POST':
            role = request.form.get('role', 'User')
            if role not in ('User', 'Admin'):
                role = 'User'
            new_password = request.form.get('password', '').strip()

            if new_password:
                cur.execute("""
                    UPDATE users SET full_name=%s, email=%s, role=%s, password=%s, first_login=FALSE
                    WHERE id=%s
                """, (
                    request.form.get('full_name'),
                    request.form.get('email', '').strip().lower(),
                    role,
                    new_password,
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

            try:
                conn.commit()
                app.logger.info(f"User updated: {id}")
                flash("User updated.")
            except Exception as e:
                conn.rollback()
                app.logger.error(f"User update error: {e}")
                flash("Update failed: email may already be in use.")

            cur.close()
            release_db_connection(conn)
            return redirect(url_for('manage_users'))

        cur.execute("SELECT * FROM users WHERE id = %s", (id,))
        user = cur.fetchone()
        cur.close()
        release_db_connection(conn)

        if not user:
            flash("User not found.")
            return redirect(url_for('manage_users'))

        return render_template('edit_user.html', user=user)
    except Exception as e:
        app.logger.error(f"Edit user error: {e}")
        flash("An error occurred. Please try again.")
        return redirect(url_for('manage_users'))


@app.route('/admin/delete_user/<int:id>', methods=['POST'])
def delete_user(id):
    if not is_admin():
        return redirect(url_for('login'))

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("SELECT username FROM users WHERE id = %s", (id,))
        user = cur.fetchone()

        if user and user['username'] == 'admin':
            flash("Cannot delete the main administrator account.")
        else:
            cur.execute("DELETE FROM users WHERE id = %s", (id,))
            conn.commit()
            app.logger.info(f"User deleted: {id}")
            flash("User deleted.")

        cur.close()
        release_db_connection(conn)
        return redirect(url_for('manage_users'))
    except Exception as e:
        app.logger.error(f"Delete user error: {e}")
        flash("An error occurred deleting the user.")
        return redirect(url_for('manage_users'))


@app.route('/admin/logs')
def admin_logs():
    if not is_admin():
        return redirect(url_for('login'))

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("SELECT * FROM login_logs ORDER BY login_time DESC LIMIT 100")
        logs = cur.fetchall()
        cur.close()
        release_db_connection(conn)

        return render_template('login_logs.html', logs=logs)
    except Exception as e:
        app.logger.error(f"Admin logs error: {e}")
        flash("An error occurred loading login logs.")
        return redirect(url_for('admin_dashboard'))


@app.route('/admin/backup')
def backup_page():
    if not is_admin():
        return redirect(url_for('login'))
    return render_template('backup.html')


@app.route('/admin/backup/download')
def backup_database():
    if not is_admin():
        return redirect(url_for('login'))

    try:
        conn = get_db_connection()
        cur = conn.cursor()

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

        cur.close()
        release_db_connection(conn)

        import json
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
    except Exception as e:
        app.logger.error(f"Database backup error: {e}")
        flash("An error occurred during database backup.")
        return redirect(url_for('admin_dashboard'))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
