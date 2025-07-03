export interface Alert {
    id: string;
    timestamp: number;
    severity: 'low' | 'medium' | 'high' | 'critical';
    message: string;
    sourceIp?: string;
    destinationIp?: string;
    protocol?: string;
    type: string;
    details: Record<string, any>;
}
