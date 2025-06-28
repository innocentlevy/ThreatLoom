import subprocess
import json
import threading
import time
import os
from datetime import datetime, timedelta
from analyzer import PacketAnalyzer
from collections import deque
import logging

class WiresharkCapture:
    def __init__(self, socketio):
        self.socketio = socketio
        self.process = None
        self.running = False
        self.thread = None
        self.interface = None
        self.analyzer = PacketAnalyzer()
        self.packet_buffer = deque(maxlen=100)  # Store last 100 packets
        self.alert_history = deque(maxlen=50)   # Store last 50 alerts
        self.active_filters = {
            'protocols': set(),  # e.g., {'TCP', 'UDP'}
            'ports': set(),      # e.g., {80, 443}
            'ips': set(),        # e.g., {'192.168.1.1'}
            'content': set()     # e.g., {'web', 'sql', 'dns'}
        }
        
        # Statistics tracking
        self.total_packets = 0
        self.packets_per_second = 0
        self.last_second_packets = 0
        self.last_stats_update = datetime.now()
        
        # Connection tracking
        self.active_connections = set()  # Set of (src_ip, src_port, dst_ip, dst_port)
        self.unique_ips = set()         # Set of unique IPs
        self.connection_timeout = 60     # Remove connections after 60 seconds of inactivity
        self.last_seen = {}             # Last time a connection was seen
        
        # Set up logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger('wireshark_siem')

    def is_running(self):
        return self.running

    def get_packet_history(self):
        """Return recent packet history"""
        return list(self.packet_buffer)

    def get_alert_history(self):
        """Return recent alert history"""
        return list(self.alert_history)

    def add_filter(self, filter_type, value):
        """Add a filter for packet capture
        filter_type: 'protocols', 'ports', 'ips', or 'content'
        value: the value to filter for
        """
        if filter_type in self.active_filters:
            self.active_filters[filter_type].add(value)
            self.logger.info(f'Added {filter_type} filter: {value}')
            return True
        return False

    def remove_filter(self, filter_type, value):
        """Remove a filter"""
        if filter_type in self.active_filters:
            self.active_filters[filter_type].discard(value)
            self.logger.info(f'Removed {filter_type} filter: {value}')
            return True
        return False

    def clear_filters(self, filter_type=None):
        """Clear all filters or filters of a specific type"""
        if filter_type:
            if filter_type in self.active_filters:
                self.active_filters[filter_type].clear()
                self.logger.info(f'Cleared all {filter_type} filters')
        else:
            for filter_set in self.active_filters.values():
                filter_set.clear()
            self.logger.info('Cleared all filters')

    def _process_packet(self, packet_line):
        """Process a single packet line from tshark output"""
        if not packet_line:
            return

        self.logger.debug(f"Processing packet line: {packet_line}")
        try:
            # Parse CSV line
            fields = [f.strip('"') for f in packet_line.strip().split(',')]
            self.logger.debug(f"Split fields: {fields}")
            
            if len(fields) < 10:  # We expect at least 10 fields
                self.logger.warning(f"Insufficient fields in packet: {packet_line}")
                return

            try:
                # Parse timestamp - tshark gives us epoch time
                timestamp = datetime.fromtimestamp(float(fields[0]))
                
                # Get protocol from tshark's protocol column and frame.protocols
                protocol_col = fields[9] if len(fields) > 9 else ''
                protocols_stack = fields[-1] if len(fields) > 14 else ''
                
                # Extract protocol name using these rules:
                # 1. If protocol column has a name, use the first word (e.g., 'TCP', 'DNS', 'TLS')
                # 2. If not, look at the protocol stack and use the highest layer protocol
                # 3. If neither works, use a generic name
                if protocol_col and not protocol_col.isdigit():
                    protocol_name = protocol_col.split()[0].upper()
                elif protocols_stack:
                    # Get the last (highest layer) protocol from the stack
                    protocols = protocols_stack.split(':')[-1].upper()
                    protocol_name = protocols.split(',')[0] if ',' in protocols else protocols
                else:
                    # Fallback to mapping IP protocol numbers
                    protocol_map = {
                        '1': 'ICMP',
                        '6': 'TCP',
                        '17': 'UDP',
                        '2': 'IGMP',
                        '8': 'EGP',
                        '9': 'IGP',
                        '47': 'GRE',
                        '50': 'ESP',
                        '51': 'AH',
                        '58': 'ICMPv6',
                        '89': 'OSPF',
                        '103': 'PIM',
                        '132': 'SCTP'
                    }
                    protocol = fields[8] if len(fields) > 8 else ''
                    protocol_name = protocol_map.get(protocol, 'IP')

                # Create packet object with properly formatted timestamp
                packet_data = {
                    'id': self.total_packets + 1,
                    'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],  # Format as YYYY-MM-DD HH:MM:SS.mmm
                    'source': fields[1],
                    'destination': fields[2],
                    'source_port': int(fields[3]) if fields[3] and fields[3].isdigit() else None,
                    'destination_port': int(fields[4]) if fields[4] and fields[4].isdigit() else None,
                    'protocol': protocol_name,
                    'length': len(packet_line),
                    'info': fields[9] if len(fields) > 9 else ''
                }
                
                # Track connections and IPs
                src_ip = packet_data['source']
                dst_ip = packet_data['destination']
                src_port = packet_data['source_port']
                dst_port = packet_data['destination_port']
                
                # Add IPs to unique set
                self.unique_ips.add(src_ip)
                self.unique_ips.add(dst_ip)
                
                # Track TCP connections
                if packet_data['protocol'] == 'TCP':
                    connection = (src_ip, src_port, dst_ip, dst_port)
                    reverse_connection = (dst_ip, dst_port, src_ip, src_port)
                    
                    # Update last seen time for both directions
                    current_time = datetime.now()
                    self.last_seen[connection] = current_time
                    self.last_seen[reverse_connection] = current_time
                    
                    # Add to active connections
                    self.active_connections.add(connection)
                    
                    # Clean up old connections
                    self._clean_old_connections(current_time)

                # Store packet in buffer
                self.packet_buffer.append(packet_data)
                
                # Emit packet immediately
                self.socketio.emit('packet_captured', packet_data)
                
                # Update statistics
                self.total_packets += 1
                self.last_second_packets += 1
                
                current_time = datetime.now()
                time_diff = (current_time - self.last_stats_update).total_seconds()
                
                if time_diff >= 1.0:  # Update stats every second
                    self.packets_per_second = self.last_second_packets / time_diff
                    self.last_second_packets = 0
                    self.last_stats_update = current_time
                    
                    # Get protocol distribution
                    protocols = {}
                    for p in self.packet_buffer:
                        proto = p['protocol']
                        protocols[proto] = protocols.get(proto, 0) + 1
                    
                    protocol_dist = [
                        {'name': proto, 'value': count}
                        for proto, count in protocols.items()
                    ]
                    
                    # Emit statistics update
                    stats = {
                        'totalPackets': self.total_packets,
                        'packetsPerSecond': round(self.packets_per_second, 2),
                        'protocolDistribution': protocol_dist,
                        'activeConnections': len(self.active_connections),
                        'uniqueIPs': len(self.unique_ips)
                    }
                    self.socketio.emit('statistics_update', stats)
                    
            except (ValueError, IndexError) as e:
                timestamp = datetime.now()
                self.logger.warning(f"Error parsing timestamp: {e}, using current time")
                
            except Exception as e:
                self.logger.error(f"Error in packet processing pipeline: {str(e)}")
                return

            # Analyze packet for security alerts
            alerts = self.analyzer.analyze_packet(packet_data)
            if alerts:
                for alert in alerts:
                    self.alert_history.append(alert)
                    self.socketio.emit('security_alert', alert)
        except json.JSONDecodeError:
            self.logger.error(f"Failed to parse packet: {packet_line}")
        except Exception as e:
            self.logger.error(f"Error processing packet: {str(e)}")

    def _get_protocol_distribution(self):
        """Get distribution of protocols in recent packets"""
        protocols = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}
        for packet in self.packet_buffer:
            proto = packet.get('protocol', 'Other')
            protocols[proto] = protocols.get(proto, 0) + 1
        return protocols

    def _capture_packets(self):
        """Start capturing packets using tshark"""
        self.logger.info("Starting packet capture thread")
        try:
            # Check if tshark is available and list interfaces
            try:
                subprocess.check_output(['which', 'tshark'])
                self.logger.info("tshark is available")
                # List available interfaces
                interfaces = subprocess.check_output(['tshark', '-D']).decode().strip().split('\n')
                self.logger.info(f"Available interfaces: {interfaces}")
            except subprocess.CalledProcessError as e:
                error_msg = "tshark is not installed. Please install it using 'brew install wireshark'"
                self.logger.error(error_msg)
                raise Exception(error_msg)

            # Build tshark command with enhanced capture options
            cmd = [
                'tshark',
                '-i', self.interface,
                '-T', 'fields',
                '-E', 'separator=,',
                '-E', 'quote=d',
                '-l',  # Line-buffered output
                '-n',  # Don't resolve names
                '-B', '4096',  # Increase buffer size
                '-P',  # Print packet summary even when writing to file
                '-Q',  # Quiet mode, only print packet lines
                '-t', 'e',  # Print time as epoch
                '-f', 'ip',  # Capture all IP traffic
                '-e', 'frame.time_epoch',  # Timestamp
                '-e', 'ip.src',  # Source IP
                '-e', 'ip.dst',  # Destination IP
                '-e', 'tcp.srcport',  # TCP source port
                '-e', 'udp.srcport',  # UDP source port
                '-e', 'tcp.dstport',  # TCP destination port
                '-e', 'udp.dstport',  # UDP destination port
                '-e', 'ip.proto',  # Protocol number
                '-e', '_ws.col.Protocol',  # Protocol name
                '-e', 'frame.len',  # Frame length
                '-e', 'tcp.flags',  # TCP flags
                '-e', 'icmp.type',  # ICMP type
                '-e', '_ws.col.Info',  # Packet info
                '-e', 'frame.protocols'  # Full protocol stack
            ]
            
            self.logger.info("Checking tshark version...")
            version_cmd = ['sudo', 'tshark', '--version']
            version = subprocess.check_output(version_cmd, universal_newlines=True)
            self.logger.info(f"Using tshark version:\n{version}")
            
            self.logger.info(f"Starting tshark with command: {' '.join(cmd)}")
            
            # Start tshark process with proper permissions
            try:
                self.process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,  # Line buffered
                    universal_newlines=True
                )
            except PermissionError:
                # If permission denied, try with sudo
                cmd.insert(0, 'sudo')
                self.process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,  # Line buffered
                    universal_newlines=True
                )
            
            # Check for immediate startup errors
            time.sleep(1)  # Give tshark a moment to start
            if self.process.poll() is not None:
                stderr_output = self.process.stderr.read()
                raise Exception(f'tshark failed to start: {stderr_output}')

            self.logger.info("Packet capture started")
            
            # Start a thread to monitor stderr
            def monitor_stderr():
                while self.running and self.process and self.process.poll() is None:
                    line = self.process.stderr.readline()
                    if line:
                        self.logger.error(f"tshark error: {line.strip()}")
            
            stderr_thread = threading.Thread(target=monitor_stderr)
            stderr_thread.daemon = True
            stderr_thread.start()
            
            # Start reading packets
            self.logger.info('Starting to read packets from tshark output')
            while self.running:
                line = self.process.stdout.readline().strip()
                if line:
                    self.logger.debug(f'Raw tshark output: {line}')
                    self._process_packet(line)
                elif self.process.poll() is not None:
                    error = self.process.stderr.read()
                    self.logger.error(f'tshark process exited unexpectedly with output: {error}')
                    break
                    
        except Exception as e:
            self.logger.error(f"Capture error: {str(e)}")
            self.running = False
        finally:
            if self.process:
                self.process.terminate()
                self.process = None

    def start(self, interface='en0'):
        self.logger.info(f"Starting packet capture on interface {interface}...")
        if not self.running:
            try:
                self.running = True
                self.interface = interface  # Store interface for _capture_packets
                self.thread = threading.Thread(target=self._capture_packets)
                self.thread.daemon = True
                self.thread.start()
                self.logger.info("Packet capture thread started successfully")
                return {"status": "success", "message": "Capture started"}
            except Exception as e:
                self.running = False
                self.logger.error(f"Failed to start packet capture: {str(e)}")
                return {"status": "error", "message": f"Failed to start capture: {str(e)}"}
        else:
            self.logger.warning("Packet capture already running")
            return {"status": "error", "message": "Capture already running"}

    def _clean_old_connections(self, current_time):
        """Remove connections that haven't been seen recently"""
        timeout = timedelta(seconds=self.connection_timeout)
        old_connections = [conn for conn, last_time in self.last_seen.items()
                          if current_time - last_time > timeout]
        
        for conn in old_connections:
            self.active_connections.discard(conn)
            del self.last_seen[conn]
    
    def stop(self):
        """Stop packet capture"""
        self.running = False
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=1)
            except Exception as e:
                self.logger.error(f"Error stopping tshark process: {str(e)}")
            finally:
                self.process = None

        if self.thread:
            try:
                self.logger.info("Waiting for capture thread to finish...")
                self.thread.join(timeout=5)
                if self.thread.is_alive():
                    self.logger.warning("Capture thread did not finish gracefully")
            except Exception as e:
                self.logger.error(f"Error joining thread: {str(e)}")
            finally:
                self.thread = None

        # Clear connection tracking
        self.active_connections.clear()
        self.last_seen.clear()
        self.unique_ips.clear()

        self.logger.info("Packet capture stopped successfully")
        return {"status": "success", "message": "Capture stopped"}

    def add_ip_to_whitelist(self, ip):
        """Add an IP to the analyzer's whitelist"""
        return self.analyzer.add_to_whitelist(ip)

    def remove_ip_from_whitelist(self, ip):
        """Remove an IP from the analyzer's whitelist"""
        self.analyzer.remove_from_whitelist(ip)
