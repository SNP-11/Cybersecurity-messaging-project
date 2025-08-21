import time
import random
import string
import datetime
import zoneinfo
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import Flask, render_template, request, redirect, url_for, session, flash

# Initialize Flask app and password hasher
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this!
ph = PasswordHasher()

# In-memory databases
users_db = {}         # username: {hash, salt}
login_attempts = {}   # username: {count, time}
messages_db = {}      # recipient: [ {from, message, shift} ]

# Security constants
MAX_ATTEMPTS = 3
LOCKOUT_TIME = 30  # seconds

def generate_salt(length=10):
    """Generate a random salt string."""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=length))

def caesar_encrypt(text, shift):
    """Encrypt text using Caesar cipher."""
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    """Decrypt text using Caesar cipher."""
    return caesar_encrypt(text, -shift)

@app.route('/')
def menu():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('menu.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users_db:
            flash('Username already exists!')
        else:
            salt = generate_salt()
            salted_password = password + salt
            hashed = ph.hash(salted_password)
            users_db[username] = {"hash": hashed, "salt": salt}
            flash('Registration successful!')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_attempt = request.form['password']
        now = time.time()
        attempts = login_attempts.get(username, {"count": 0, "time": 0})

        # Rate limiting
        if attempts["count"] >= MAX_ATTEMPTS and now - attempts["time"] < LOCKOUT_TIME:
            flash('User is locked out. Try again later.')
            return render_template('login.html')

        user_data = users_db.get(username)
        if not user_data:
            flash('User does not exist.')
            return render_template('login.html')

        salt = user_data["salt"]
        hashed = user_data["hash"]
        try:
            ph.verify(hashed, password_attempt + salt)
            mfa_code = request.form.get('mfa_code')
            if mfa_code == "123456":
                session['username'] = username
                login_attempts[username] = {"count": 0, "time": now}
                return redirect(url_for('menu'))
            else:
                flash('MFA failed.')
                login_attempts[username] = {"count": attempts["count"] + 1, "time": now}
        except VerifyMismatchError:
            flash('Incorrect password!')
            login_attempts[username] = {"count": attempts["count"] + 1, "time": now}
    return render_template('login.html')

@app.route('/reset', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']
        if username not in users_db:
            flash('User does not exist.')
            return render_template('reset.html')
        salt = generate_salt()
        salted = new_password + salt
        new_hash = ph.hash(salted)
        users_db[username] = {"hash": new_hash, "salt": salt}
        flash('Password reset successful.')
        return redirect(url_for('login'))
    return render_template('reset.html')

@app.route('/message', methods=['GET', 'POST'])
def message():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        recipient = request.form['recipient']
        msg = request.form['message']
        shift = int(request.form.get('shift', 3))  # Default shift is 3
        print("SENDER:", session['username'])  # Debug: print sender
        encrypted_msg = caesar_encrypt(msg, shift)
        if recipient not in messages_db:
            messages_db[recipient] = []
        messages_db[recipient].append({
            'from': session['username'],
            'message': encrypted_msg,
            'shift': shift,
            'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat()
        })
        flash('Message sent and encrypted!')
    return render_template('message.html')

@app.route('/inbox')
def inbox():
    if 'username' not in session:
        return redirect(url_for('login'))
    user_msgs = messages_db.get(session['username'], [])
    display_msgs = []
    local_tz = zoneinfo.ZoneInfo("America/New_York")  # Change to your timezone
    for m in user_msgs:
        ts = m['timestamp']
        if isinstance(ts, str):
            ts = datetime.datetime.fromisoformat(ts)
        # Convert UTC to local time
        ts = ts.astimezone(local_tz)
        display_msgs.append({
            'from': m['from'],
            'encrypted': m['message'],
            'decrypted': caesar_decrypt(m['message'], m['shift']),
            'timestamp': ts
        })
    return render_template('inbox.html', messages=display_msgs)

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out successfully.')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, threaded=True)