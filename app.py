import eventlet
import ssl
import eventlet.wsgi

# Monkey patching for eventlet
eventlet.monkey_patch()
from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_socketio import SocketIO, emit, disconnect
from threading import Thread
from flask import jsonify
from geopy.distance import geodesic
import base64
from cryptography.fernet import Fernet
import qrcode
from io import BytesIO
from flask import send_file
# Option 2: Import just the datetime class
from datetime import datetime
import hashlib
import time


attendance_log = []
# Initialize Flask and Flask-SocketIO
app = Flask(__name__)
app.config.from_pyfile('config.py')
app.secret_key = app.config['SECRET_KEY']
socketio = SocketIO(app, cors_allowed_origins="*")

# Generate a key for encryption
# You should store this key securely and load it from a safe place
ENCRYPTION_KEY = app.config['ENCRYPTION_KEY']
cipher_suite = Fernet(ENCRYPTION_KEY)

# Define the geofence center and radius (e.g., classroom location)
GEOFENCE_CENTER = (13.125015, 77.589764)  # Example coordinates
GEOFENCE_RADIUS_KM = 0.1  # 100 meters

connected_students = {}
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# In-memory user storage for demonstration purposes
users = {
    'student1': {'password': 'password123', 'role': 'student', 'name': 'Student One'},
    'student2': {'password': 'password123', 'role': 'student', 'name': 'Student Two'},
    'student3': {'password': 'password123', 'role': 'student', 'name': 'Student Three'},
    'student4': {'password': 'password123', 'role': 'student', 'name': 'Student Four'},
    'instructor1': {'password': 'password123', 'role': 'instructor', 'name': 'Instructor One'}
}

class User(UserMixin):
    def __init__(self, username, role, name):
        self.id = username
        self.role = role
        self.name = name


@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated and current_user.role == 'student':
        connected_students[current_user.id] = {'name': current_user.name, 'time': time.time()}
        socketio.emit('connected', {'id': current_user.id, 'name': current_user.name})  # Broadcasts to all clients

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated and current_user.role == 'student':
        connected_students.pop(current_user.id, None)
        socketio.emit('disconnected', {'id': current_user.id, 'name': current_user.name})  # Broadcasts to all clients


# Monitor disconnected students every 10 minutes
TIMEOUT_PERIOD = 600
def monitor_disconnected_students():
    while True:
        current_time = time.time()
        for user_id, info in list(connected_students.items()):
            if current_time - info['time'] > TIMEOUT_PERIOD:
                connected_students.pop(user_id, None)
        time.sleep(60)

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        user = User(user_id, users[user_id]['role'], users[user_id].get('name', ''))
        return user
    return None

# Instructor route to monitor connected students
@app.route('/monitor')
@login_required
def monitor():
    if current_user.role != 'instructor':
        return "Unauthorized", 403
    return render_template('monitor.html')


@app.route('/save_fingerprint', methods=['POST'])
def save_fingerprint():
    data = request.get_json()
    
    # Concatenate device info to create a unique string
    fingerprint_string = f"{data['userAgent']}_{data['language']}_{data['screenResolution']}_{data['timezone']}_{data['platform']}"
    
    # Hash the fingerprint string to create a unique ID
    fingerprint_id = hashlib.sha256(fingerprint_string.encode()).hexdigest()
    
    # Optionally, store fingerprint in session or a persistent store (like a database)
    session['device_fingerprint'] = fingerprint_id

    return jsonify({'fingerprint_id': fingerprint_id})

# Endpoint to fetch connected students
@app.route('/get_connected_students')
@login_required
def get_connected_students():
    if current_user.role != 'instructor':
        return jsonify({'error': 'Unauthorized'}), 403
    connected_list = [{'id': student_id, 'name': info['name'], 'status': 'connected'}
                      for student_id, info in connected_students.items()]
    return jsonify(connected_list)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and password == users[username]['password']:
            # Pass the name to the User constructor
            user = User(username, users[username]['role'], users[username]['name'])  # Add the name here
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'student':
        return render_template('dashboard_student.html')
    elif current_user.role == 'instructor':
        # Use the datetime class directly
        return render_template('dashboard_instructor.html', attendance=attendance_log, current_date=datetime.now().strftime("%Y-%m-%d"))
    else:
        return "Role not recognized.", 403





@app.route('/mark_attendance')
@login_required
def mark_attendance():
    if current_user.role != 'student':
        return "Unauthorized", 403
    return render_template('mark_attendance.html')

@app.route('/submit_location', methods=['POST'])
@login_required
def submit_location():
    if current_user.role != 'student':
        return "Unauthorized", 403
    data = request.get_json()
    latitude = data.get('latitude')
    longitude = data.get('longitude')
    user_location = (latitude, longitude)
    distance = geodesic(GEOFENCE_CENTER, user_location).km
    if distance <= GEOFENCE_RADIUS_KM:
        session['geolocation_verified'] = True
        session['latitude'] = latitude  # Store location for attendance logging
        session['longitude'] = longitude
        return '', 200
    else:
        return 'You are outside the allowed area.', 400


@app.route('/scan_qr')
@login_required
def scan_qr():
    if current_user.role != 'student':
        return "Unauthorized", 403
    if not session.get('geolocation_verified'):
        return redirect(url_for('mark_attendance'))
    return render_template('scan_qr.html')

@app.route('/submit_qr', methods=['POST'])
@login_required
def submit_qr():
    if current_user.role != 'student':
        return "Unauthorized", 403

    data = request.get_json()
    qr_data = data.get('qr_data')

    try:
        # Decrypt QR code data and validate geolocation
        decrypted_token = cipher_suite.decrypt(qr_data.encode('utf-8')).decode('utf-8')
        token_location = tuple(map(float, decrypted_token.split(',')))
        student_location = (session.get('latitude'), session.get('longitude'))

        # Check if the scanned QR code's location is within the allowed range
        if geodesic(token_location, student_location).km <= GEOFENCE_RADIUS_KM:
            # Add student to connected_students and attendance_log
            connected_students[current_user.id] = {'name': current_user.name, 'time': time.time()}
            socketio.emit('connected', {'id': current_user.id, 'name': current_user.name})  # No broadcast=True

            attendance_log.append({
                'id': current_user.id,
                'name': current_user.name,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })

            # Emit event to notify connected clients
            return "Attendance marked successfully.", 200
        else:
            return 'Location mismatch; attendance denied.', 403

    except Exception as e:
        return str(e), 400



@app.route('/generate_qr')
@login_required
def generate_qr():
    if current_user.role != 'instructor':
        return "Unauthorized", 403
    return render_template('generate_qr.html')


@app.route('/qr_code')
@login_required
def qr_code():
    if current_user.role != 'instructor':
        return "Unauthorized", 403

    # Get the geofence center
    location_data = f"{GEOFENCE_CENTER[0]},{GEOFENCE_CENTER[1]}"
    encrypted_token = cipher_suite.encrypt(location_data.encode('utf-8'))

    # Generate QR code
    img = qrcode.make(encrypted_token)

    # Save the image to a BytesIO object
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    buffered.seek(0)

    return send_file(buffered, mimetype='image/png')

@app.route('/qr_code_data')
@login_required
def qr_code_data():
    if current_user.role != 'instructor':
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Get the user's location from the session (or set a default for testing)
    latitude = session.get('latitude', 'Unknown')  # Replace with actual location logic if needed
    longitude = session.get('longitude', 'Unknown')  # Replace with actual location logic if needed
    
    # Create token with timestamp and location
    import time
    token_data = f"{time.time()}|{latitude},{longitude}"
    encrypted_token = cipher_suite.encrypt(token_data.encode('utf-8'))

    # Generate QR code
    img = qrcode.make(encrypted_token)

    # Convert the image to a base64-encoded string
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_data = base64.b64encode(buffered.getvalue()).decode('utf-8')

    # Return the image data as JSON
    return jsonify({'img_data': img_data})

# Store active sessions and last heartbeat time for each user
active_sessions = {}

@app.route('/heartbeat', methods=['POST'])
@login_required
def heartbeat():
    user_id = current_user.id
    active_sessions[user_id] = time.time()  # Record the time of the latest heartbeat
    return jsonify({"status": "connected"})


from threading import Thread

# Timeout period for heartbeat (10 minutes)
TIMEOUT_PERIOD = 600  

def monitor_heartbeats():
    while True:
        current_time = time.time()
        disconnected_users = [
            user_id for user_id, last_heartbeat in active_sessions.items()
            if current_time - last_heartbeat > TIMEOUT_PERIOD
        ]
        
        # Mark users as disconnected if they exceeded the timeout period
        for user_id in disconnected_users:
            active_sessions.pop(user_id, None)
            print(f"User {user_id} has been disconnected due to inactivity.")
        
        time.sleep(60)  # Check every minute

Thread(target=monitor_disconnected_students, daemon=True).start()

# SSL configuration and server initialization
if __name__ == '__main__':
    cert = 'cert.pem'
    key = 'key.pem'
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    ssl_context.load_cert_chain(certfile=cert, keyfile=key)
    listener = eventlet.wrap_ssl(eventlet.listen(('0.0.0.0', 5000)), certfile=cert, keyfile=key, server_side=True)
    eventlet.wsgi.server(listener, app)
