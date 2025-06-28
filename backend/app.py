import logging
import logging.config
import os
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict
from flask import Flask, request, jsonify
from flask_socketio import SocketIO
from capture import WiresharkCapture
from analyzer import PacketAnalyzer
from config import ANALYZER_CONFIG, LOGGING_CONFIG
from api_docs import swagger_ui_blueprint, SWAGGER_URL, get_api_spec
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, JWTManager
from test_endpoints import test_bp
from flask_cors import CORS
from models import db, User
from passlib.hash import pbkdf2_sha256
from functools import wraps
from auth import register_user, admin_required

# Initialize logging
logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Initialize Flask app
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'your-jwt-secret-key')
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wireshark_siem.db')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///' + db_path)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
CORS(app)
jwt = JWTManager(app)

# Register test endpoints
app.register_blueprint(test_bp)

# Register Swagger UI blueprint
app.register_blueprint(swagger_ui_blueprint, url_prefix=SWAGGER_URL)

@app.route('/api/swagger.json')
def swagger():
    return jsonify(get_api_spec())

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

def create_default_admin():
    """Create a default admin user if none exists"""
    try:
        logger.info('Checking for existing admin users...')
        admin = User.query.filter_by(is_admin=True).first()
        if not admin:
            logger.info('No admin user found, creating default admin...')
            username = os.environ.get('ADMIN_USERNAME', 'admin')
            password = os.environ.get('ADMIN_PASSWORD', 'admin123456789')
            logger.info('Using username: ' + username)
            admin = User(username=username, is_admin=True)
            admin.set_password(password)
            logger.info('Adding admin user to session...')
            db.session.add(admin)
            logger.info('Committing session...')
            db.session.commit()
            logger.info('Created default admin user successfully')
            
            # Verify admin was created
            check_admin = User.query.filter_by(username=username).first()
            if check_admin:
                logger.info('Verified admin user exists with id ' + str(check_admin.id))
            else:
                logger.error('Failed to verify admin user creation')
        else:
            logger.info('Admin user already exists with id ' + str(admin.id))
    except Exception as e:
        logger.error('Error creating default admin: ' + str(e))
        import traceback
        logger.error(traceback.format_exc())

# Create database tables if they don't exist
with app.app_context():
    logger.info('Using database at: ' + db_path)
    logger.info('Creating database tables...')
    db.create_all()
    logger.info('Database tables created')
    logger.info('Creating default admin user...')
    create_default_admin()

@app.route('/api/auth/setup', methods=['POST'])
def setup():
    """Initial setup endpoint to create the first admin user"""
    try:
        # Try to query users table
        User.query.first()
    except Exception:
        # If there's an error, it means the table doesn't exist
        db.create_all()
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Missing username or password'}), 400
    
    if len(password) < 12:
        return jsonify({'error': 'Password must be at least 12 characters long'}), 400
    
    success, message = register_user(username, password, is_admin=True)
    if not success:
        return jsonify({'error': message}), 400
    
    return jsonify({'message': 'Admin user created successfully'})

# Initialize analyzer and capture
analyzer = PacketAnalyzer(config=ANALYZER_CONFIG)
capture = WiresharkCapture(socketio)

# Track last statistics update
last_stats_update = datetime.now()

# Statistics storage
stats = {
    'total_packets': 0,
    'protocols': defaultdict(int),
    'top_talkers': defaultdict(int),
    'alerts_count': 0,
    'start_time': None
}

def update_statistics(packet):
    """Update real-time statistics"""
    global stats
    
    if not stats['start_time']:
        stats['start_time'] = datetime.now()
    
    stats['total_packets'] += 1
    stats['protocols'][packet['protocol']] += 1
    stats['top_talkers'][packet['source']] += 1

@app.route('/api/auth/login', methods=['POST'])
def login():
    logger.info('Login attempt received')
    data = request.get_json()
    logger.info('Login request data: ' + str(data))
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        logger.error('Missing username or password')
        return jsonify({'error': 'Missing username or password'}), 400
    
    logger.info('Looking up user in database: ' + username)
    try:
        user = User.query.filter_by(username=username).first()
        logger.info('Database query result: ' + str(user))
        
        if not user:
            logger.error('User not found: ' + username)
            return jsonify({'error': 'Invalid username or password'}), 401
        
        logger.info('Found user: ' + user.username + ', id: ' + str(user.id) + ', checking password...')
        logger.info('User password hash: ' + user.password_hash)
        
        # Try to verify the password
        try:
            password_valid = user.check_password(password)
            logger.info('Password check result: ' + str(password_valid))
            
            if not password_valid:
                logger.error('Password check failed for user: ' + username)
                return jsonify({'error': 'Invalid username or password'}), 401
        except Exception as e:
            logger.error('Error during password check: ' + str(e))
            return jsonify({'error': 'Error during authentication'}), 500
        
        logger.info('Password check successful for user: ' + username)
        access_token = create_access_token(identity=user.id)
        response = {
            'access_token': access_token,
            'user': {
                'id': user.id,
                'username': user.username,
                'is_admin': user.is_admin
            }
        }
        logger.info('Login response prepared: ' + str(response))
        return jsonify(response)
    except Exception as e:
        logger.error('Error during login: ' + str(e))
        import traceback
        logger.error(traceback.format_exc())
        return jsonify({'error': 'Server error during login'}), 500

@app.route('/api/auth/register', methods=['POST'])
@admin_required()
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Missing username or password'}), 400
    
    success, message = register_user(username, password)
    if not success:
        return jsonify({'error': message}), 400
    
    return jsonify({'message': 'User registered successfully'})

@app.route('/api/interfaces')
def get_interfaces():
    try:
        interfaces = subprocess.check_output(['tshark', '-D']).decode().strip().split('\n')
        # Parse interface names from tshark output (format: "1. en0 (Wi-Fi)")
        parsed_interfaces = []
        for line in interfaces:
            parts = line.split('.')
            if len(parts) != 2:
                continue
            id_part = parts[0].strip()
            rest = parts[1].strip()
            
            # Extract name without description
            name = rest.split()[0].strip()
            # Get description if exists (everything in parentheses)
            description = ''
            if '(' in rest and ')' in rest:
                description = rest[rest.find('(')+1:rest.find(')')]
            
            parsed_interfaces.append({
                'id': id_part,
                'name': name,
                'description': description
            })
        
        return jsonify({
            'interfaces': parsed_interfaces
        })
    except subprocess.CalledProcessError as e:
        logger.error('Failed to get interfaces: {}'.format(str(e)))
        return jsonify({'error': 'Failed to get network interfaces'}), 500

@app.route('/api/status')
@jwt_required()
def get_status():
    return jsonify({
        'isCapturing': capture.is_running(),
        'activeInterface': capture.interface if capture.is_running() else None
    })

@app.route('/api/statistics')
def get_statistics():
    protocol_distribution = [
        {'name': proto, 'value': count}
        for proto, count in stats['protocols'].items()
    ]
    
    return jsonify({
        'totalPackets': stats['total_packets'],
        'packetsPerSecond': stats['total_packets'] / ((datetime.now() - stats['start_time']).seconds + 1) if stats['start_time'] else 0,
        'protocolDistribution': protocol_distribution
    })

@app.route('/api/alerts')
def get_alerts():
    return jsonify({
        'alerts': capture.get_alerts()
    })

@app.route('/api/packets/recent')
def get_recent_packets():
    return jsonify({
        'packets': capture.get_recent_packets()
    })

@app.route('/api/whitelist', methods=['GET', 'POST', 'DELETE'])
@admin_required()
def manage_whitelist():
    if request.method == 'POST':
        data = request.get_json()
        ip = data.get('ip')
        if not ip:
            return jsonify({'error': 'No IP address provided'}), 400
        
        capture.add_to_whitelist(ip)
        return jsonify({'message': 'Added {} to whitelist'.format(ip)})
    elif request.method == 'DELETE':
        data = request.get_json()
        ip = data.get('ip')
        if not ip:
            return jsonify({'error': 'No IP address provided'}), 400
            
        capture.remove_from_whitelist(ip)
        return jsonify({'message': 'Removed {} from whitelist'.format(ip)})
    else:
        return jsonify({
            'whitelist': list(capture.get_whitelist())
        })

@socketio.on('start_capture')
def handle_start_capture(data=None):
    # Default to en0 (typical external interface on macOS) if no interface specified
    interface = data.get('interface', 'en0') if data else 'en0'
    logger.info('Starting capture on interface: {}'.format(interface))
    try:
        # Get list of available interfaces
        interfaces = subprocess.check_output(['tshark', '-D']).decode().strip().split('\n')
        logger.info('Available interfaces: {}'.format(interfaces))
        
        # Start capture
        result = capture.start(interface=interface)
        if result.get('status') == 'success':
            logger.info('Packet capture started successfully')
            socketio.emit('capture_status', {'status': 'running', 'interface': interface})
            socketio.emit('capture_started')
        else:
            error_msg = result.get('message', 'Unknown error starting capture')
            logger.error('Failed to start capture: {}'.format(error_msg))
            socketio.emit('capture_error', {'message': error_msg})
    except Exception as e:
        error_msg = str(e)
        logger.error('Error starting capture: {}'.format(error_msg))
        socketio.emit('capture_error', {'message': error_msg})

@socketio.on('stop_capture')
def handle_stop_capture():
    try:
        logger.info('Stopping capture...')
        capture.stop()
        logger.info('Capture stopped successfully')
        socketio.emit('capture_status', {'status': 'stopped'})
        socketio.emit('capture_stopped')
    except Exception as e:
        error_msg = 'Error stopping capture: {}'.format(str(e))
        logger.error(error_msg)
        socketio.emit('capture_error', {'message': error_msg})

@socketio.on('connect')
def handle_connect():
    logger.info('Client connected: {}'.format(request.sid))
    try:
        # Send current status
        if capture.is_running():
            socketio.emit('capture_status', {'status': 'running'})
        else:
            socketio.emit('capture_status', {'status': 'stopped'})
            
        # Send any existing data
        socketio.emit('statistics_update', get_statistics())
        socketio.emit('packet_history', get_recent_packets())
    except Exception as e:
        logger.error('Error in connect handler: {}'.format(str(e)))

@socketio.on('disconnect')
def handle_disconnect():
    logger.info('Client disconnected: {}'.format(request.sid))

@socketio.on('packet_captured')
def handle_packet_captured(packet):
    try:
        global last_stats_update
        current_time = datetime.now()
        
        logger.debug('Packet captured: {}'.format(packet))
        
        # Analyze packet for security threats
        alerts = analyzer.analyze_packet(packet)
        
        # Emit alerts if any were detected
        for alert in alerts:
            socketio.emit('security_alert', alert)
            
        # Always update basic statistics
        update_statistics(packet)
        
        # Emit statistics update based on configured interval
        stats_interval = timedelta(seconds=ANALYZER_CONFIG['thresholds'].get('stats_update_interval', 5))
        if current_time - last_stats_update >= stats_interval:
            # Convert protocol stats to the format expected by frontend
            protocol_distribution = [
                {'name': proto, 'value': count}
                for proto, count in stats['protocols'].items()
            ]
            
            elapsed_seconds = (current_time - stats['start_time']).total_seconds() if stats['start_time'] else 1
            packets_per_second = stats['total_packets'] / elapsed_seconds if elapsed_seconds > 0 else 0
            
            logger.debug('Emitting statistics update: {} packets, {:.2f} pps'.format(
                stats["total_packets"], packets_per_second))
            
            socketio.emit('statistics_update', {
                'totalPackets': stats['total_packets'],
                'packetsPerSecond': packets_per_second,
                'protocolDistribution': protocol_distribution
            })
            
            last_stats_update = current_time
    except Exception as e:
        logger.error(f"Error handling packet: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())

@socketio.on('security_alert')
def handle_security_alert(alert):
    stats['alerts_count'] += 1

if __name__ == '__main__':
    logger.info('Starting application...')
    socketio.run(app, host='0.0.0.0', port=5001)
