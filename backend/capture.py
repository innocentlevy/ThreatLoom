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
        
        # Socket tracking
        self.connected_sids = set()   # Track connected client SIDs
        
        # Set up logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger('wireshark_siem')

    def is_running(self):
        return self.running

    def get_packet_history(self):
        """Return recent packet history"""
        return list(self.packet_buffer)

    @staticmethod
    def get_interfaces():
        """Get list of available network interfaces using tshark with sudo"""
        try:
            # First try without sudo
            try:
                process = subprocess.run(['tshark', '-D'],
                                       capture_output=True,
                                       text=True,
                                       check=True)
            except subprocess.CalledProcessError:
                # If that fails, try with sudo
                process = subprocess.run(['sudo', '-n', 'tshark', '-D'],
                                       capture_output=True,
                                       text=True,
                                       check=True)
            
            interfaces = []
            for line in process.stdout.strip().split('\n'):
                # tshark -D output format is: "1. en0 (Wi-Fi)" or similar
                if line:
                    # Split on first period and strip whitespace
                    parts = line.split('.', 1)
                    if len(parts) == 2:
                        interface_info = parts[1].strip()
                        # Extract interface name (everything before the space or parenthesis)
                        interface_name = interface_info.split(' ')[0]
                        interfaces.append({
                            'name': interface_name,
                            'description': interface_info
                        })
            
            if not interfaces:
                raise Exception('No network interfaces found')
                
            return interfaces
            
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr or str(e)
            if 'permission denied' in str(error_msg).lower():
                raise Exception('Permission denied. Please make sure you have sudo privileges to run tshark.')
            raise Exception(f'Failed to get network interfaces: {error_msg}')
        except Exception as e:
            raise Exception(f'Error getting network interfaces: {str(e)}')

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
                
                # Extract protocol information from various fields
                protocol_col = fields[7] if len(fields) > 7 else ''
                protocols_stack = fields[8] if len(fields) > 8 else ''
                ip_proto = fields[9] if len(fields) > 9 else ''
                tls_info = fields[10] if len(fields) > 10 else ''
                http_info = fields[11] if len(fields) > 11 else ''
                dns_info = fields[12] if len(fields) > 12 else ''
                
                # Determine protocol using protocol stack
                protocol_name = 'OTHER'
                protocols_found = set()
                
                # Check protocol stack first as it contains all layers
                if protocols_stack:
                    stack = protocols_stack.upper()
                    # Common protocols to look for
                    protocol_checks = [
                        'ARP', 'ICMP', 'TCP', 'UDP',  # Lower layer protocols
                        'DNS', 'HTTP', 'HTTPS', 'TLS', 'SSH',  # Application protocols
                        'DHCP', 'SMTP', 'FTP', 'TELNET', 'NTP'  # Additional protocols
                    ]
                    
                    for proto in protocol_checks:
                        if proto in stack:
                            protocols_found.add(proto)
                
                # Add protocol from column if not already found
                if protocol_col and not protocol_col.isdigit():
                    proto = protocol_col.split()[0].upper()
                    if proto in {'TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'HTTPS', 'TLS', 'SSH', 'ARP'}:
                        protocols_found.add(proto)
                
                # Check specific protocol fields
                if dns_info:
                    protocols_found.add('DNS')
                if http_info:
                    protocols_found.add('HTTP')
                if tls_info:
                    protocols_found.add('TLS')
                
                # Check IP protocol numbers
                if ip_proto:
                    protocol_map = {
                        '1': 'ICMP',
                        '6': 'TCP',
                        '17': 'UDP'
                    }
                    if ip_proto in protocol_map:
                        protocols_found.add(protocol_map[ip_proto])
                
                # Choose the most relevant protocol to display
                # Prioritize application layer protocols if present
                app_protocols = {'DNS', 'HTTP', 'HTTPS', 'TLS', 'SSH', 'FTP', 'SMTP'}
                transport_protocols = {'TCP', 'UDP'}
                network_protocols = {'ICMP', 'ARP'}
                
                if protocols_found & app_protocols:
                    protocol_name = next(iter(protocols_found & app_protocols))
                elif protocols_found & transport_protocols:
                    protocol_name = next(iter(protocols_found & transport_protocols))
                elif protocols_found & network_protocols:
                    protocol_name = next(iter(protocols_found & network_protocols))
                elif protocols_found:
                    protocol_name = next(iter(protocols_found))

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
                    'info': fields[7] if len(fields) > 7 else ''
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
                
                # Update statistics every second
                current_time = datetime.now()
                time_diff = (current_time - self.last_stats_update).total_seconds()
                
                if time_diff >= 1.0:
                    # Calculate packets per second
                    self.packets_per_second = self.last_second_packets / time_diff
                    self.last_second_packets = 0
                    self.last_stats_update = current_time
                    
                    # Get protocol distribution from recent packets
                    protocols = {}
                    for p in self.packet_buffer:
                        proto = p.get('protocol', 'OTHER')
                        if proto:
                            protocols[proto] = protocols.get(proto, 0) + 1
                    
                    # Sort protocols by count and take top 5
                    sorted_protocols = sorted(protocols.items(), key=lambda x: x[1], reverse=True)[:5]
                    protocol_dist = [
                        {'name': proto, 'value': count}
                        for proto, count in sorted_protocols
                    ]
                    
                    # Ensure we have at least one protocol
                    if not protocol_dist:
                        protocol_dist = [{'name': 'NO DATA', 'value': 0}]
                    
                    # Calculate packets per second as integer
                    pps = int(round(self.packets_per_second))
                    
                    # Emit statistics update
                    stats = {
                        'totalPackets': self.total_packets,
                        'packetsPerSecond': pps,
                        'protocolDistribution': protocol_dist,
                        'activeConnections': len(self.active_connections),
                        'uniqueIPs': len(self.unique_ips)
                    }
                    self.logger.info(f'Emitting stats update: {stats}')
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

    def start(self, interface, sudo_password):
        """Start packet capture on the specified interface"""
        if self.running:
            return {"status": "error", "message": "Capture already running"}

        if not self.connected_sids:
            return {"status": "error", "message": "No clients connected"}

        self.interface = interface
        self.running = True

        # Create and start capture thread
        self.thread = threading.Thread(target=self._capture_packets, args=(sudo_password,))
        self.thread.daemon = True
        self.thread.start()

        # Wait a short time to check if capture started successfully
        time.sleep(0.5)
        if not self.running or not self.process:
            self.running = False
            return {"status": "error", "message": "Failed to start capture"}

        # Notify all connected clients
        self.socketio.emit('capture_started', {
            'status': 'running',
            'interface': interface
        })

        return {"status": "success", "message": "Capture started successfully"}

    def _get_protocol_distribution(self):
        """Get distribution of protocols in recent packets"""
        protocols = {}
        for packet in self.packet_buffer:
            proto = packet.get('protocol', 'Other')
            if proto and not proto.isdigit():  # Ensure we have a valid protocol name
                proto = proto.upper()  # Normalize protocol names to uppercase
                protocols[proto] = protocols.get(proto, 0) + 1
            else:
                protocols['Other'] = protocols.get('Other', 0) + 1
            
        # Sort protocols by count and take top 10 to avoid cluttering the chart
        sorted_protocols = sorted(protocols.items(), key=lambda x: x[1], reverse=True)[:10]
        return [{'name': proto, 'value': count} for proto, count in sorted_protocols]

    def _capture_packets(self, sudo_password):
        """Start capturing packets using tshark"""
        try:
            # Build tshark command with enhanced capture options
            cmd = [
                'sudo', '-S', 'tshark',
                '-i', self.interface,  # Use passed interface parameter
                '-T', 'fields',
                '-E', 'separator=,',
                '-E', 'quote=d',
                '-l',  # Line-buffered output
                '-n',  # Don't resolve names
                '-B', '4096',  # Increase buffer size
                '-P',  # Print packet summary even when writing to file
                '-Q',  # Quiet mode, only print packet lines
                '-t', 'e',  # Print time as epoch
                # No filter - capture all protocols
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
            
            self.logger.info(f"Starting tshark with command: {' '.join(cmd)}")
            
            # Start tshark process
            self.process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # Line buffered
            )
            
            # Send sudo password
            if not self.process.stdin:
                self.logger.error('No stdin pipe available')
                self.running = False
                return
            
            self.process.stdin.write(sudo_password + '\n')
            self.process.stdin.flush()
        
            # Wait a short time to check if process started
            time.sleep(0.1)
            if self.process.poll() is not None:
                error = self.process.stderr.read() if self.process.stderr else 'Process failed to start'
                self.logger.error(f'tshark process failed to start: {error}')
                self.running = False
                return

            # Start reading packets
            while self.running and self.process and self.process.poll() is None:
                try:
                    line = self.process.stdout.readline().strip()
                    if line:
                        self._process_packet(line)
                except Exception as e:
                    self.logger.error(f"Error reading packet: {str(e)}")
                    continue

            # Check why we exited the loop
            if self.process and self.process.poll() is not None:
                error = self.process.stderr.read() if self.process.stderr else 'Process terminated'
                self.logger.error(f'tshark process exited unexpectedly: {error}')
                self.running = False

        except Exception as e:
            self.logger.error(f"Capture error: {str(e)}")
            self.running = False
        finally:
            # Ensure cleanup
            if self.process:
                try:
                    self.process.terminate()
                    self.process.wait(timeout=1)
                except Exception as cleanup_error:
                    self.logger.error(f"Error during cleanup: {cleanup_error}")
                finally:
                    self.process = None
            self.running = False

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
        if not self.running:
            return {"status": "error", "message": "Capture not running"}

        self.running = False

        # Stop tshark process
        if self.process:
            try:
                # Get tshark pid
                pid = self.process.pid
                # Use sudo kill to stop tshark
                subprocess.run(['sudo', 'kill', str(pid)], check=True)
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    subprocess.run(['sudo', 'kill', '-9', str(pid)], check=True)
                except Exception as e:
                    self.logger.error(f"Error force killing process: {str(e)}")
            except Exception as e:
                self.logger.error(f"Error stopping process: {str(e)}")
            finally:
                self.process = None

        if self.thread:
            self.logger.info("Waiting for capture thread to finish...")
            try:
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

        # Notify all connected clients
        self.socketio.emit('capture_stopped', {
            'status': 'stopped',
            'interface': self.interface
        })

        self.logger.info("Packet capture stopped successfully")
        return {"status": "success", "message": "Capture stopped"}

    def add_ip_to_whitelist(self, ip):
        """Add an IP to the analyzer's whitelist"""
        self.analyzer.add_ip_to_whitelist(ip)

    def remove_ip_from_whitelist(self, ip):
        """Remove an IP from the analyzer's whitelist"""
        self.analyzer.remove_ip_from_whitelist(ip)
