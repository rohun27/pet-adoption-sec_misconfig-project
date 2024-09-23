import sqlite3
from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
import os
import secrets

app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_urlsafe(16)
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USE_SSL"] = True
app.config["MAIL_USERNAME"] = "your_email@gmail.com"
app.config["MAIL_PASSWORD"] = "your_email_password"

bcrypt = Bcrypt(app)
mail = Mail(app)

# Connect to SQLite database
conn = sqlite3.connect('pet_finder.db', check_same_thread=False)
cursor = conn.cursor()

# Create table if it doesn't exist
cursor.execute('''CREATE TABLE IF NOT EXISTS users
                   (id INTEGER PRIMARY KEY, username TEXT, email TEXT, password TEXT, role TEXT, otp TEXT)''')
conn.commit()

# Create table if it doesn't exist
cursor.execute('''CREATE TABLE IF NOT EXISTS admin
                   (id INTEGER PRIMARY KEY, username TEXT, email TEXT, password TEXT)''')
conn.commit()

@app.route('/')
def index():
    return render_template('app.html')

@app.route('/signin', methods=['POST'])
def signin():
    username = request.form['username']
    password = request.form['password']
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    if user:
        if bcrypt.check_password_hash(user[3], password):
            # Generate OTP and send to email
            otp = secrets.token_urlsafe(6)
            msg = Message('Pet Finder OTP', sender='your_email@gmail.com', recipients=[user[2]])
            msg.body = f'Your OTP is: {otp}'
            mail.send(msg)
            cursor.execute("UPDATE users SET otp=? WHERE username=?", (otp, username))
            conn.commit()
            return jsonify({'message': 'OTP sent to email'})
        else:
            return jsonify({'message': 'Invalid password'}), 401
    else:
        return jsonify({'message': 'User not found'}), 404

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    username = request.form['username']
    otp = request.form['otp']
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    if user:
        if user[5] == otp:
            # Login successful, redirect to dashboard
            return redirect(url_for('dashboard'))
        else:
            return jsonify({'message': 'Invalid OTP'}), 401
    else:
        return jsonify({'message': 'User not found'}), 404

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    role = request.form['role']
    hashed_password = bcrypt.generate_password_hash(password)
    cursor.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                   (username, email, hashed_password, role))
    conn.commit()
    return jsonify({'message': 'User created successfully'})

@app.route('/change_password', methods=['POST'])
def change_password():
    username = request.form['username']
    old_password = request.form['old_password']
    new_password = request.form['new_password']
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    if user:
        if bcrypt.check_password_hash(user[3], old_password):
            hashed_new_password = bcrypt.generate_password_hash(new_password)
            cursor.execute("UPDATE users SET password=? WHERE username=?", (hashed_new_password, username))
            conn.commit()
            return jsonify({'message': 'Password changed successfully'})
        else:
            return jsonify({'message': 'Invalid old password'}), 401
    else:
        return jsonify({'message': 'User not found'}), 404

@app.route('/admin_signin', methods=['POST'])
def admin_signin():
    username = request.form['username']
    password = request.form['password']
    cursor.execute("SELECT * FROM admin WHERE username=?", (username,))
    admin = cursor.fetchone()
    if admin:
        if bcrypt.check_password_hash(admin[3], password):
            # Login successful, redirect to admin dashboard
            return redirect(url_for('admin_dashboard'))
        else:
            return jsonify({'message': ' Invalid password'}), 401
    else:
        return jsonify({'message': 'Admin not found'}), 404

@app.route('/admin_change_password', methods=['POST'])
def admin_change_password():
    username = request.form['username']
    old_password = request.form['old_password']
    new_password = request.form['new_password']
    cursor.execute("SELECT * FROM admin WHERE username=?", (username,))
    admin = cursor.fetchone()
    if admin:
        if bcrypt.check_password_hash(admin[3], old_password):
            hashed_new_password = bcrypt.generate_password_hash(new_password)
            cursor.execute("UPDATE admin SET password=? WHERE username=?", (hashed_new_password, username))
            conn.commit()
            return jsonify({'message': 'Password changed successfully'})
        else:
            return jsonify({'message': 'Invalid old password'}), 401
    else:
        return jsonify({'message': 'Admin not found'}), 404

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.after_request
def set_csp_header(response):
    csp = "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' https://fonts.googleapis.com; img-src 'self' https://petfinder.com; font-src 'self' https://fonts.gstatic.com"
    response.headers["Content-Security-Policy"] = csp
    return response

if __name__ == '__main__':
    app.run(debug=True)