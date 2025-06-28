from datetime import datetime, timedelta
import ipaddress
import re

class PacketAnalyzer:
    def __init__(self, config=None):
        # Default configuration
        self.config = {
            'thresholds': {
                'port_scan': 100,          # ports per minute
                'ddos': 3000,             # packets per minute
                'ddos_bytes': 5242880,    # bytes per minute (5MB)
                'burst_allowance': 500,   # allowed burst packets in burst window
                'burst_window': 10,       # burst window in seconds
                'max_packet_age': 60,     # seconds to keep packet history
                'alert_cooldown': 180,    # seconds between similar alerts
                'stats_update_interval': 5, # statistics update interval
            },
            'patterns': {
                'sql_injection': r'(?i)(union\s+select|select.*from|insert\s+into|delete\s+from)',
                'xss': r'(?i)(<script>|javascript:)',
                'command_injection': r'(?i)([;&|`]\s*[$({]|\b(cat|wget|curl)\b)',
                'credential_leak': r'(?i)(password=|apikey=|secret=|token=)'
            }
        }
        
        # Override defaults with provided config
        if config:
            self.config['thresholds'].update(config.get('thresholds', {}))
            self.config['patterns'].update(config.get('patterns', {}))
        
        # Initialize tracking data
        self.ip_packet_counts = {}    # Track packet counts per IP
        self.ip_byte_counts = {}      # Track bytes per IP
        self.ip_burst_counts = {}     # Track short-term bursts
        self.last_alert_time = {}
        self.alert_dedup_cache = {}   # Cache for alert deduplication
        self.whitelist = set()
        
        # Load suspicious patterns
        self.suspicious_patterns = self.config['patterns']

    def is_private_ip(self, ip):
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def analyze_packet(self, packet):
        """
        Analyze a packet for potential security threats
        Returns a list of alerts if any threats are detected
        """
        alerts = []
        timestamp = datetime.fromisoformat(packet['timestamp'])
        src_ip = packet['source']
        dst_ip = packet['destination']
        protocol = packet['protocol']
        info = packet['info']

        # Skip analysis for whitelisted IPs
        if src_ip in self.whitelist or dst_ip in self.whitelist:
            return alerts

        # Clean old packet counts
        current_time = datetime.now()
        self._clean_old_data(current_time)

        # Get packet size (if available)
        packet_size = packet.get('size', 0)
        if isinstance(packet_size, str):
            try:
                packet_size = int(packet_size)
            except ValueError:
                packet_size = 0
        
        # Update packet counts and sizes for rate limiting
        self._update_packet_counts(src_ip, timestamp, packet_size)

        # Check for various types of attacks
        potential_alerts = []
        potential_alerts.extend(self._check_rate_limits(src_ip, timestamp))
        potential_alerts.extend(self._check_payload_patterns(info))
        potential_alerts.extend(self._check_suspicious_protocols(protocol, info))

        # Filter alerts based on cooldown
        alerts = self._filter_alerts_cooldown(potential_alerts, current_time)

        return alerts

    def _update_packet_counts(self, src_ip, timestamp, packet_size=0):
        # Initialize counters for this IP if not exists
        if src_ip not in self.ip_packet_counts:
            self.ip_packet_counts[src_ip] = []
            self.ip_byte_counts[src_ip] = []
            self.ip_burst_counts[src_ip] = []
        
        # Add new packet timestamp and size
        self.ip_packet_counts[src_ip].append(timestamp)
        self.ip_byte_counts[src_ip].append((timestamp, packet_size))
        
        # Track bursts (last 10 seconds)
        burst_window = timestamp - timedelta(seconds=10)
        self.ip_burst_counts[src_ip] = [t for t in self.ip_burst_counts[src_ip] if t > burst_window]
        self.ip_burst_counts[src_ip].append(timestamp)

    def _clean_old_data(self, current_time):
        # Remove old packet data
        max_age = timedelta(seconds=self.config['thresholds']['max_packet_age'])
        cutoff_time = current_time - max_age

        for ip in list(self.ip_packet_counts.keys()):
            # Clean packet counts
            self.ip_packet_counts[ip] = [
                ts for ts in self.ip_packet_counts[ip]
                if ts > cutoff_time
            ]
            
            # Clean byte counts
            self.ip_byte_counts[ip] = [
                (ts, size) for ts, size in self.ip_byte_counts[ip]
                if ts > cutoff_time
            ]
            
            # Remove IP if no data left
            if not self.ip_packet_counts[ip]:
                del self.ip_packet_counts[ip]
                del self.ip_byte_counts[ip]
                if ip in self.ip_burst_counts:
                    del self.ip_burst_counts[ip]

    def _filter_alerts_cooldown(self, alerts, current_time):
        filtered_alerts = []
        cooldown = timedelta(seconds=self.config['thresholds']['alert_cooldown'])

        for alert in alerts:
            alert_key = f"{alert['type']}:{alert.get('source_ip', '')}"
            last_time = self.last_alert_time.get(alert_key)

            if not last_time or (current_time - last_time) > cooldown:
                self.last_alert_time[alert_key] = current_time
                filtered_alerts.append(alert)

        return filtered_alerts

    def _check_rate_limits(self, src_ip, timestamp):
        alerts = []
        
        # Get current metrics
        packet_count = len(self.ip_packet_counts[src_ip])
        burst_count = len(self.ip_burst_counts[src_ip])
        byte_count = sum(size for _, size in self.ip_byte_counts[src_ip])
        
        # Calculate rates per minute
        packets_per_minute = packet_count * (60 / self.config['thresholds']['max_packet_age'])
        bytes_per_minute = byte_count * (60 / self.config['thresholds']['max_packet_age'])
        
        # Generate alert key for deduplication with more granular time window
        alert_key = f'ddos:{src_ip}:{timestamp.strftime("%Y%m%d%H%M%S")[:11]}'
        
        # Check for DDoS conditions with improved detection
        is_ddos = False
        ddos_details = []
        severity = 'medium'
        
        # Check packet rate (with burst allowance)
        if packets_per_minute > self.config['thresholds']['ddos']:
            if burst_count > self.config['thresholds']['burst_allowance']:
                is_ddos = True
                severity = 'high' if packets_per_minute > self.config['thresholds']['ddos'] * 1.5 else 'medium'
                ddos_details.append(f'High packet rate: {packets_per_minute:.0f} packets/minute')
        
        # Check byte rate
        if bytes_per_minute > self.config['thresholds']['ddos_bytes']:
            is_ddos = True
            severity = 'high' if bytes_per_minute > self.config['thresholds']['ddos_bytes'] * 1.5 else 'medium'
            ddos_details.append(f'High traffic volume: {bytes_per_minute/1024/1024:.2f} MB/minute')
        
        # Add alert if DDoS detected and not in dedup cache
        if is_ddos and alert_key not in self.alert_dedup_cache:
            # Store additional context in dedup cache
            self.alert_dedup_cache[alert_key] = {
                'timestamp': timestamp,
                'packet_rate': packets_per_minute,
                'byte_rate': bytes_per_minute,
                'severity': severity
            }
            
            alerts.append({
                'type': 'ddos',
                'timestamp': timestamp.isoformat(),
                'source_ip': src_ip,
                'severity': severity,
                'message': f'Potential DDoS attack detected from {src_ip}',
                'details': ' | '.join(ddos_details)
            })
        
        # Clean old dedup cache entries
        self._clean_dedup_cache(timestamp)
        
        return alerts
        
    def _clean_dedup_cache(self, current_time):
        """Clean old entries from the alert deduplication cache"""
        cache_ttl = timedelta(minutes=3)  # Reduced from 5 to 3 minutes for more responsive alerts
        cutoff_time = current_time - cache_ttl
        
        # Remove old cache entries
        for key in list(self.alert_dedup_cache.keys()):
            entry = self.alert_dedup_cache[key]
            if isinstance(entry, dict) and entry['timestamp'] < cutoff_time:
                del self.alert_dedup_cache[key]
            elif not isinstance(entry, dict) and entry < cutoff_time:  # Legacy format
                del self.alert_dedup_cache[key]

    def _check_payload_patterns(self, payload):
        """Check for malicious patterns in packet payload"""
        alerts = []
        
        for attack_type, pattern in self.suspicious_patterns.items():
            if re.search(pattern, payload):
                alerts.append({
                    'type': attack_type,
                    'severity': 'high',
                    'details': f'Suspicious pattern detected: {attack_type}',
                    'pattern': pattern
                })
        
        return alerts

    def _check_suspicious_protocols(self, protocol, info):
        """Check for suspicious protocol usage"""
        alerts = []
        suspicious_combinations = {
            'HTTP': ['GET /admin', 'PUT /', 'DELETE /'],
            'DNS': ['zone transfer', 'ANY'],
            'SMB': ['\\\\ADMIN$', '\\\\C$'],
        }
        
        if protocol in suspicious_combinations:
            for pattern in suspicious_combinations[protocol]:
                if pattern.lower() in info.lower():
                    alerts.append({
                        'type': 'suspicious_protocol',
                        'severity': 'medium',
                        'protocol': protocol,
                        'details': f'Suspicious {protocol} activity detected: {pattern}'
                    })
        
        return alerts

    def add_to_whitelist(self, ip):
        """Add an IP to the whitelist"""
        try:
            ipaddress.ip_address(ip)  # Validate IP format
            self.whitelist.add(ip)
            return True
        except ValueError:
            return False

    def remove_from_whitelist(self, ip):
        """Remove an IP from the whitelist"""
        self.whitelist.discard(ip)
