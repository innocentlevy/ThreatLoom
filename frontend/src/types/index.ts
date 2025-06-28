export interface Packet {
    id: number;
    timestamp: string;
    source: string;
    source_ip?: string;
    source_port?: number;
    destination: string;
    destination_ip?: string;
    destination_port?: number;
    protocol: string;
    length: number;
    info: string;
    flags?: string[];
}

export interface Alert {
    id: number;
    severity: 'high' | 'medium' | 'low';
    message: string;
    timestamp: string;
    type: string;
    details: string;
}

export interface Statistics {
    totalPackets: number;
    packetsPerSecond: number;
    protocolDistribution: {
        name: string;
        value: number;
    }[];
}

export interface SystemStatus {
    status: string;
    capture_active: boolean;
    uptime: string;
    total_packets: number;
    alerts_count: number;
}
