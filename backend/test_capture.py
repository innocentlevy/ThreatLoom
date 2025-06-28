import time
from capture import WiresharkCapture
import subprocess
import threading
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('test_capture')

# Mock SocketIO for testing
class MockSocketIO:
    def emit(self, event, data):
        logger.info(f"Event: {event}, Data: {data}")

def generate_test_traffic():
    """Generate some test ICMP traffic"""
    time.sleep(2)  # Wait for capture to start
    logger.info("Generating test ICMP traffic...")
    subprocess.run(['ping', '-c', '5', 'localhost'])
    logger.info("Finished generating test traffic")

if __name__ == '__main__':
    # Create capture instance with mock socketio
    mock_socketio = MockSocketIO()
    capture = WiresharkCapture(mock_socketio)
    
    # Start packet capture
    logger.info("Starting packet capture...")
    capture.start(interface='lo0')  # Use loopback interface for testing
    
    # Start traffic generation in a separate thread
    traffic_thread = threading.Thread(target=generate_test_traffic)
    traffic_thread.daemon = True
    traffic_thread.start()
    
    try:
        # Run for 10 seconds
        logger.info("Running test for 10 seconds...")
        time.sleep(10)
    finally:
        # Stop capture
        logger.info("Stopping packet capture...")
        capture.stop()
        logger.info("Test complete")
