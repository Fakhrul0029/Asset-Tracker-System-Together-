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
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, Response
from flask_wtf.csrf import CSRFProtect
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'jtdi_secure_master_2026')
app.permanent_session_lifetime = timedelta(hours=8)

csrf = CSRFProtect(app)

DATABASE_URL = os.environ.get('DATABASE_URL')

# Simple connection function
def get_db_connection():
    if not DATABASE_URL:
        return None
    url = DATABASE_URL
    if url.startswith('postgres://'):
        url = url.replace('postgres://', 'postgresql://', 1)
    try:
        return psycopg2.connect(url)
    except Exception as e:
        print(f"DB Connection Error: {e}")
        return None

def is_admin():
    return session.get('role') == 'Admin'

@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        # Check for admin hardcoded login first (for testing)
        if email == 'admin@jtdi.gov.my' and password == 'Admin123':
            session.permanent = True
            session.update({
                'user': 'admin',
                'role': 'Admin',
                'full_name': 'System Administrator',
                'email': 'admin@jtdi.gov.my'
            })
            return redirect(url_for('dashboard'))
        
        try:
            conn = get_db_connection()
            if conn:
                cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
                cur.execute("SELECT * FROM users WHERE email = %s", (email,))
                user = cur.fetchone()
                cur.close()
                conn.close()
                
                if user and user['password'] == password:
                    session.permanent = True
                    session.update({
                        'user': user['username'],
                        'role': user['role'],
                        'full_name': user['full_name'] or user['username'],
                        'email': user['email']
                    })
                    return redirect(url_for('dashboard'))
            flash("Invalid email or password.")
        except Exception as e:
            print(f"Login error: {e}")
            flash("An error occurred during login.")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
