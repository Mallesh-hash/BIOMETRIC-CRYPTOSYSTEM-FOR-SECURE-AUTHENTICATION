from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
import cv2
import numpy as np
import face_recognition
import os
from datetime import datetime
import base64
import sqlite3
# werkzeug is user for password hashing and checking
# werkzeug is a comprehensive WSGI web application library for python
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['DATABASE'] = 'face_auth.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database initialization
def get_db():
    db = sqlite3.connect(app.config['DATABASE'])
    db.row_factory = sqlite3.Row
    return db

def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                face_encoding TEXT,
                registered_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        db.commit()

init_db()

@app.route('/')
def home():
    if 'username' in session:
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', [session['username']]).fetchone()
        return render_template('dashboard.html', user=user)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', [username]).fetchone()
        
        if user and check_password_hash(user['password'], password):
            session['username'] = user['username']
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        
        flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        name = request.form.get('name')
        
        db = get_db()
        try:
            db.execute(
                'INSERT INTO users (username, password, name, email) VALUES (?, ?, ?, ?)',
                [username, generate_password_hash(password), name, email]
            )
            db.commit()
            flash('Account created successfully! Please register your face.', 'success')
            return redirect(url_for('register_face_page', username=username))
        except sqlite3.IntegrityError:
            flash('Username or email already exists', 'danger')
    
    return render_template('register.html')

@app.route('/register-face/<username>')
def register_face_page(username):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ?', [username]).fetchone()
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('register'))
    return render_template('register_face.html', username=username)

@app.route('/face-login')
def face_login_page():
    return render_template('face_login.html')

@app.route('/process-face', methods=['POST'])
def process_face():
    data = request.get_json()
    username = data.get('username')
    image_data = data['image'].split(',')[1]
    
    # Decode base64 image
    img_bytes = base64.b64decode(image_data)
    img_array = np.frombuffer(img_bytes, np.uint8)
    img = cv2.imdecode(img_array, cv2.IMREAD_COLOR)
    rgb_img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
    
    # Detect face
    face_locations = face_recognition.face_locations(rgb_img)
    if not face_locations:
        return jsonify({'success': False, 'error': 'No face detected'})
    
    # Get face encoding 
    # face encoding use AES-128 hash function
    face_encoding = face_recognition.face_encodings(rgb_img, face_locations)[0]
    
    if username:
        # Registration flow
        db = get_db()
        db.execute(
            'UPDATE users SET face_encoding = ? WHERE username = ?',
            [face_encoding.tobytes().hex(), username]
        )
        db.commit()
        
        # Save face image
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{app.config['UPLOAD_FOLDER']}/{username}_{timestamp}.jpg"
        cv2.imwrite(filename, img)
        
        return jsonify({'success': True, 'message': 'Face registered successfully'})
    else:
        # Login flow
        db = get_db()
        users = db.execute('SELECT username, face_encoding FROM users WHERE face_encoding IS NOT NULL').fetchall()
        
        for user in users:
            if user['face_encoding']:
                stored_encoding = np.frombuffer(bytes.fromhex(user['face_encoding']), dtype=np.float64)
                matches = face_recognition.compare_faces([stored_encoding], face_encoding)
                
                if matches[0]:
                    session['username'] = user['username']
                    return jsonify({'success': True, 'username': user['username']})
        
        return jsonify({'success': False, 'error': 'Failed to capture image'})

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)