import logging
import logging.config
import os
import subprocess
import json
from datetime import datetime, timedelta
from collections import defaultdict
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, disconnect
from capture import WiresharkCapture
from analyzer import PacketAnalyzer
from config import ANALYZER_CONFIG, LOGGING_CONFIG
from api_docs import swagger_ui_blueprint, SWAGGER_URL, get_api_spec
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, JWTManager, decode_token
from test_endpoints import test_bp
from flask_cors import CORS
from models import db, User
from passlib.hash import pbkdf2_sha256
from functools import wraps
from auth import register_user, admin_required
from sudo_auth import verify_sudo_password

def authenticated_only(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not request.sid:
            logger.error('Socket auth error: No session ID')
            disconnect()
            return False

        try:
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f'Socket auth error: {str(e)}')
            disconnect()
            return False
    return wrapped

# Initialize logging
logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Initialize Flask app configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'your-jwt-secret-key-here')
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_HEADER_TYPE'] = 'Bearer'
app.config['JWT_ERROR_MESSAGE_KEY'] = 'error'
app.config['JWT_IDENTITY_CLAIM'] = 'sub'
app.config['JWT_DECODE_ALGORITHMS'] = ['HS256']

# Database configuration
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wireshark_siem.db')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///' + db_path)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions in correct order
jwt = JWTManager(app)
db.init_app(app)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Register test endpoints
app.register_blueprint(test_bp)

# Register Swagger UI blueprint
app.register_blueprint(swagger_ui_blueprint, url_prefix=SWAGGER_URL)

# JWT error handlers
@jwt.invalid_token_loader
def invalid_token_callback(error_string):
    return jsonify({
        'error': 'Invalid token',
        'message': error_string
    }), 401

@jwt.unauthorized_loader
def missing_token_callback(error_string):
    return jsonify({
        'error': 'Authorization required',
        'message': error_string
    }), 401

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({
        'error': 'Token has expired',
        'message': 'Please log in again'
    }), 401

@app.route('/api/swagger.json')
def swagger():
    return jsonify(get_api_spec())

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', logger=True, engineio_logger=True)

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
        # Create access token with user ID as identity (convert to string)
        access_token = create_access_token(
            identity=str(user.id),
            additional_claims={
                'username': user.username,
                'is_admin': user.is_admin
            }
        )
        response = {
            'access_token': access_token,
            'user': {
                'id': user.id,
                'username': user.username,
                'is_admin': user.is_admin
            }
        }
        logger.info('Generated access token for user: %s', username)
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

@app.route('/api/interfaces', methods=['GET'])
@jwt_required()
def get_interfaces():
    try:
        # Get current user identity
        current_user_id = get_jwt_identity()
        if not current_user_id or not isinstance(current_user_id, str):
            return jsonify({'error': 'Invalid authentication token'}), 401
            
        # Convert string ID back to integer
        try:
            user_id = int(current_user_id)
        except ValueError:
            return jsonify({'error': 'Invalid user ID in token'}), 401
            
        # Get interfaces
        interfaces = WiresharkCapture.get_interfaces()
        return jsonify({
            'interfaces': interfaces
        })
    except Exception as e:
        error_msg = str(e)
        status_code = 403 if 'permission denied' in error_msg.lower() else 500
        return jsonify({
            'error': error_msg
        }), status_code

@app.route('/api/status')
@jwt_required()
def get_status():
    return jsonify({
        'isCapturing': capture.is_running(),
        'activeInterface': capture.interface if capture.is_running() else None
    })

@app.route('/api/statistics')
@jwt_required()
def get_statistics():
    try:
        if not stats.get('protocols') or not stats.get('total_packets') or not stats.get('start_time'):
            return jsonify({
                'totalPackets': 0,
                'packetsPerSecond': 0,
                'protocolDistribution': []
            })

        protocol_distribution = [
            {'name': proto, 'value': count}
            for proto, count in stats['protocols'].items()
        ]
        
        elapsed_seconds = (datetime.now() - stats['start_time']).seconds + 1
        packets_per_second = stats['total_packets'] / elapsed_seconds if elapsed_seconds > 0 else 0

        return jsonify({
            'totalPackets': stats['total_packets'],
            'packetsPerSecond': packets_per_second,
            'protocolDistribution': protocol_distribution
        })
    except Exception as e:
        logger.error(f'Error getting statistics: {str(e)}')
        return jsonify({'error': 'Failed to retrieve statistics'}), 500

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

@app.route('/api/sudo-auth', methods=['POST'])
@jwt_required()
def verify_sudo():
    data = request.get_json()
    if not data or 'password' not in data:
        return jsonify({'error': 'Password is required'}), 400
    
    success, message = verify_sudo_password(data['password'])
    if success:
        return jsonify({'message': message})
    return jsonify({'error': message}), 401

@socketio.on('start_capture')
@authenticated_only
def handle_start_capture(data=None):
    try:
        logger.info('Received start_capture event with data: %s', data)
        
        if not data or 'interface' not in data:
            error = 'Interface name is required'
            logger.error(error)
            socketio.emit('capture_error', error)
            return {'status': 'error', 'message': error}
            
        if 'sudoPassword' not in data:
            error = 'Sudo password is required'
            logger.error(error)
            socketio.emit('capture_error', error)
            return {'status': 'error', 'message': error}

        interface = data['interface']
        sudo_password = data['sudoPassword']
        
        # Verify sudo password
        logger.info('Verifying sudo password...')
        success, message = verify_sudo_password(sudo_password)
        if not success:
            logger.error('Sudo verification failed: %s', message)
            socketio.emit('capture_error', 'Invalid sudo password')
            return {'status': 'error', 'message': 'Invalid sudo password'}

        logger.info('Starting capture on interface %s', interface)

        if capture.is_running():
            error = 'Capture is already running'
            logger.error(error)
            socketio.emit('capture_error', error)
            return {'status': 'error', 'message': error}

        try:
            # Emit early response
            logger.info('Emitting capture_starting event...')
            socketio.emit('capture_starting', {'interface': interface})
            
            # Start packet capture
            logger.info('Starting capture with sudo password...')
            result = capture.start(interface, sudo_password)
            logger.info('Capture start result: %s', result)
            
            if result['status'] == 'success':
                logger.info('Capture started successfully')
                response = {'status': 'running', 'interface': interface}
                logger.info('Emitting capture_started with: %s', response)
                socketio.emit('capture_started', response)
                return {'status': 'success', 'message': 'Capture started successfully'}
            else:
                error = result.get('message', 'Failed to start capture')
                logger.error('Capture start failed: %s', error)
                socketio.emit('capture_error', error)
                return {'status': 'error', 'message': error}
        except Exception as e:
            error_msg = str(e)
            logger.error('Unexpected error starting capture: %s', error_msg)
            socketio.emit('capture_error', error_msg)
            return {'status': 'error', 'message': error_msg}
    except Exception as e:
        error_msg = str(e)
        logger.error('Unexpected error starting capture: %s', error_msg)
        socketio.emit('capture_error', error_msg)
        return {'status': 'error', 'message': error_msg}

@socketio.on('stop_capture')
def handle_stop_capture():
    try:
        logger.info('Received stop_capture event')
        logger.info('Stopping capture...')
        capture.stop()
        logger.info('Capture stopped successfully')
        socketio.emit('capture_status', {'status': 'stopped'})
        socketio.emit('capture_stopped')
    except Exception as e:
        error_msg = 'Error stopping capture: {}'.format(str(e))
        logger.error(error_msg)
        socketio.emit('capture_error', {'message': error_msg})

def authenticated_only(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not request.args.get('auth'):
            disconnect()
            return False
        try:
            auth = json.loads(request.args.get('auth'))
            token = auth.get('token')
            if not token:
                disconnect()
                return False
            decoded = decode_token(token)
            if not decoded:
                disconnect()
                return False
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f'Socket auth error: {str(e)}')
            disconnect()
            return False
    return wrapped

@socketio.on('connect')
def handle_connect(auth):
    try:
        if not auth or 'token' not in auth:
            logger.error('Error in connect handler: Missing token in auth data')
            return False

        token = auth.get('token')
        if not token:
            logger.error('Error in connect handler: Token not found in auth data')
            return False

        try:
            decoded = decode_token(token)
            if not decoded:
                logger.error('Error in connect handler: Invalid token')
                return False

            logger.info('Client connected with valid token: {}'.format(request.sid))
            capture.connected_sids.add(request.sid)
            return True
        except Exception as e:
            logger.error('Error in connect handler: Token verification failed - {}'.format(str(e)))
            return False
    except Exception as e:
        logger.error('Error in connect handler: {}'.format(str(e)))
        return False

@socketio.on('disconnect')
def handle_disconnect():
    if request.sid in capture.connected_sids:
        capture.connected_sids.remove(request.sid)
    logger.info('Client disconnected: {}'.format(request.sid))

@socketio.on('packet_captured')
def handle_packet_captured(packet):
    try:
        global last_stats_update
        current_time = datetime.now()
        
        logger.debug('Packet captured: {}'.format(packet))
        
        # Emit packet to frontend
        socketio.emit('packet', packet)
        
        # Analyze packet for security threats
        alerts = analyzer.analyze_packet(packet)
        
        # Emit alerts if any were detected
        for alert in alerts:
            socketio.emit('alert', alert)
            
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
            
            socketio.emit('stats', {
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
