export interface Statistics {
    totalPackets: number;
    packetsPerSecond: number;
    protocolDistribution: Array<{ protocol: string; count: number }>;
    activeConnections: number;
    uniqueHosts: number;
    packetsAnalyzed: number;
    alertsGenerated: number;
    totalBytes: number;
    bytesPerSecond: number;
}
