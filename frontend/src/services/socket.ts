import { io, Socket } from 'socket.io-client';
import { Packet } from '../models/packet';
import { Alert } from '../models/alert';
import { Statistics } from '../models/statistics';

export interface CaptureOptions {
    interface: string;
    sudoPassword?: string;
}

export interface NetworkInterfaceData {
    name: string;
    description: string;
}

export interface CaptureStatus {
    status: string;
    interface?: string;
}

export class SocketService {
    private static instance: SocketService;
    private socket: Socket | null = null;
    private status: string = 'disconnected';
    private interface?: string;
    private interfaces: NetworkInterfaceData[] = [];
    private packetHandlers: Array<(packet: Packet) => void> = [];
    private alertHandlers: Array<(alert: Alert) => void> = [];
    private statsHandlers: Array<(stats: Statistics) => void> = [];
    private statusHandlers: Array<(status: CaptureStatus) => void> = [];
    private interfaceHandlers: Array<(interfaces: NetworkInterfaceData[]) => void> = [];
    private connectErrorHandlers: Array<(error: Error) => void> = [];
    private disconnectHandlers: Array<() => void> = [];
    private sudoRequiredHandlers: Array<() => void> = [];

    private constructor() {}

    public static getInstance(): SocketService {
        if (!SocketService.instance) {
            SocketService.instance = new SocketService();
        }
        return SocketService.instance;
    }

    public onPacket(handler: (packet: Packet) => void): void {
        this.packetHandlers.push(handler);
    }

    public offPacket(handler: (packet: Packet) => void): void {
        this.packetHandlers = this.packetHandlers.filter(h => h !== handler);
    }

    public onAlert(handler: (alert: Alert) => void): void {
        this.alertHandlers.push(handler);
    }

    public offAlert(handler: (alert: Alert) => void): void {
        this.alertHandlers = this.alertHandlers.filter(h => h !== handler);
    }

    public onStats(handler: (stats: Statistics) => void): void {
        this.statsHandlers.push(handler);
    }

    public offStats(handler: (stats: Statistics) => void): void {
        this.statsHandlers = this.statsHandlers.filter(h => h !== handler);
    }

    public onStatus(handler: (status: CaptureStatus) => void): void {
        this.statusHandlers.push(handler);
    }

    public offStatus(handler: (status: CaptureStatus) => void): void {
        this.statusHandlers = this.statusHandlers.filter(h => h !== handler);
    }

    public onConnectError(handler: (error: Error) => void): void {
        this.connectErrorHandlers.push(handler);
    }

    public offConnectError(handler: (error: Error) => void): void {
        this.connectErrorHandlers = this.connectErrorHandlers.filter(h => h !== handler);
    }

    public onDisconnect(handler: () => void): void {
        this.disconnectHandlers.push(handler);
    }

    public offDisconnect(handler: () => void): void {
        this.disconnectHandlers = this.disconnectHandlers.filter(h => h !== handler);
    }

    public onSudoRequired(handler: () => void): void {
        this.sudoRequiredHandlers.push(handler);
    }

    public offSudoRequired(handler: () => void): void {
        this.sudoRequiredHandlers = this.sudoRequiredHandlers.filter(h => h !== handler);
    }

    public onInterfaces(handler: (interfaces: NetworkInterfaceData[]) => void): void {
        this.interfaceHandlers.push(handler);
        // If we already have interfaces, call the handler immediately
        if (this.interfaces.length > 0) {
            handler(this.interfaces);
        }
    }

    public offInterfaces(handler: (interfaces: NetworkInterfaceData[]) => void): void {
        this.interfaceHandlers = this.interfaceHandlers.filter(h => h !== handler);
    }

    public async fetchInterfaces(): Promise<void> {
        try {
            const token = localStorage.getItem('token');
            if (!token) throw new Error('No authentication token found');

            const response = await fetch('http://localhost:5001/api/interfaces', {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Accept': 'application/json'
                }
            });

            if (!response.ok) {
                if (response.status === 401) {
                    throw new Error('Authentication required');
                }
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            if (data.error) {
                throw new Error(data.error);
            }

            this.interfaces = data.interfaces;
            this.interfaceHandlers.forEach(handler => handler(this.interfaces));
        } catch (error) {
            console.error('Failed to fetch interfaces:', error);
            throw error;
        }
    }

    public async connect(): Promise<void> {
        // If already connected, return
        if (this.socket?.connected) {
            return;
        }
        
        // If socket exists but not connected, disconnect it first
        if (this.socket) {
            this.socket.disconnect();
            this.socket = null;
        }
        return new Promise<void>((resolve, reject) => {
            if (!this.socket) {
                const token = localStorage.getItem('token');
                if (!token) {
                    reject(new Error('No authentication token found'));
                    return;
                }
                this.socket = io('http://localhost:5001', {
                    auth: { token },
                    reconnection: true,
                    reconnectionAttempts: 5,
                    reconnectionDelay: 1000,
                    timeout: 10000,
                    transports: ['polling'], // Use only polling for now
                    path: '/socket.io' // Add explicit path
                });
                this.setupEventHandlers();
                
                // Set up promise resolution
                this.socket.once('connect', () => resolve());
                this.socket.once('connect_error', (error: Error) => reject(error));
                
                // Set a connection timeout
                const timeoutId = setTimeout(() => {
                    if (!this.socket?.connected) {
                        const error = new Error('Connection timeout');
                        this.connectErrorHandlers.forEach(handler => handler(error));
                        reject(error);
                    }
                }, 5000);
            } else {
                resolve();
            }
        });
    }

    public async startCapture(options: CaptureOptions): Promise<void> {
        return new Promise<void>((resolve, reject) => {
            if (!this.socket) {
                reject(new Error('Not connected to server'));
                return;
            }

            if (!this.socket.connected) {
                reject(new Error('Socket is not connected'));
                return;
            }

            if (!options.interface) {
                reject(new Error('No interface selected'));
                return;
            }

            if (!options.sudoPassword) {
                reject(new Error('Sudo password is required'));
                return;
            }

            const timeoutId = setTimeout(() => {
                this.socket?.off('capture_started', handleStarted);
                this.socket?.off('capture_error', handleError);
                reject(new Error('Capture start timeout - no response from server'));
            }, 10000);

            const handleStarted = (data: { interface?: string }) => {
                clearTimeout(timeoutId);
                this.socket?.off('capture_started', handleStarted);
                this.socket?.off('capture_error', handleError);
                this.status = 'running';
                this.interface = data.interface;
                this.statusHandlers.forEach(handler => handler({ status: this.status, interface: this.interface }));
                resolve();
            };

            const handleError = (error: any) => {
                clearTimeout(timeoutId);
                this.socket?.off('capture_started', handleStarted);
                this.socket?.off('capture_error', handleError);
                const errorMessage = error?.message || error?.toString() || 'Unknown error starting capture';
                reject(new Error(errorMessage));
            };

            this.socket.once('capture_started', handleStarted);
            this.socket.once('capture_error', handleError);
            
            // Log for debugging (without the actual password)
            console.log('Emitting start_capture:', {
                interface: options.interface,
                has_sudo_password: !!options.sudoPassword
            });

            // Make sure to use the exact field name expected by the backend
            this.socket.emit('start_capture', {
                interface: options.interface,
                sudoPassword: options.sudoPassword, // Try camelCase version
                sudo_password: options.sudoPassword, // Also send snake_case version
                requireSudo: true
            });

            // Also try the start_capture_sudo event
            this.socket.emit('start_capture_sudo', {
                interface: options.interface,
                password: options.sudoPassword
            });
        });
    }

    public async stopCapture(): Promise<void> {
        return new Promise<void>((resolve, reject) => {
            if (!this.socket) {
                reject(new Error('Not connected'));
                return;
            }

            const timeoutId = setTimeout(() => {
                reject(new Error('Stop capture timeout'));
            }, 10000);

            const handleStopped = () => {
                clearTimeout(timeoutId);
                this.status = 'stopped';
                this.interface = undefined;
                this.statusHandlers.forEach(handler => handler({ status: this.status, interface: this.interface }));
                resolve();
            };

            const handleError = (error: Error) => {
                clearTimeout(timeoutId);
                reject(error);
            };

            this.socket.once('capture_stopped', handleStopped);
            this.socket.once('capture_error', handleError);
            this.socket.emit('stop_capture');
        });
    }

    public async getStats(): Promise<Statistics> {
        return new Promise<Statistics>((resolve, reject) => {
            if (!this.socket) {
                reject(new Error('Not connected'));
                return;
            }

            const timeoutId = setTimeout(() => {
                reject(new Error('Get stats timeout'));
            }, 5000);

            const handleStats = (stats: Statistics) => {
                clearTimeout(timeoutId);
                this.statsHandlers.forEach(handler => handler(stats));
                resolve(stats);
            };

            this.socket.once('stats', handleStats);
            this.socket.emit('get_stats');
        });
    }

    public getStatus(): CaptureStatus {
        return {
            status: this.status,
            interface: this.interface
        };
    }

    public disconnect(): void {
        if (this.socket) {
            this.socket.disconnect();
            this.socket = null;
            this.status = 'disconnected';
            this.interface = undefined;
            this.statusHandlers.forEach(handler => handler({ status: this.status }));
            this.disconnectHandlers.forEach(handler => handler());
        }
    }

    private setupEventHandlers(): void {
        if (!this.socket) return;

        // Remove any existing listeners to prevent duplicates
        this.socket.removeAllListeners();

        // Setup basic event handlers
        this.socket.on('connect', () => {
            console.log('Socket connected');
            this.status = 'connected';
            this.statusHandlers.forEach(handler => handler({ status: this.status }));
        });

        // Add sudo required handler
        this.socket.on('sudo_required', () => {
            console.log('Sudo required event received');
            this.sudoRequiredHandlers.forEach(handler => handler());
        });

        this.socket.on('disconnect', () => {
            console.log('Socket disconnected');
            this.status = 'disconnected';
            this.interface = undefined;
            this.statusHandlers.forEach(handler => handler({ status: this.status }));
            this.disconnectHandlers.forEach(handler => handler());
        });

        this.socket.on('connect_error', (error: Error) => {
            console.error('Socket connection error:', error);
            this.connectErrorHandlers.forEach(handler => handler(error));
        });

        // Setup application-specific event handlers
        this.socket.on('packet_captured', (packet: Packet) => {
            console.log('Socket received packet:', packet);
            // Ensure packet has all required fields and proper types
            const processedPacket: Packet = {
                ...packet,
                id: packet.id?.toString() || `pkt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                timestamp: typeof packet.timestamp === 'string' ? new Date(packet.timestamp).getTime() : Date.now(),
                protocol: packet.protocol?.toUpperCase() || 'UNKNOWN',
                length: typeof packet.length === 'number' ? packet.length : 0,
                source_port: packet.source_port || undefined,
                destination_port: packet.destination_port || undefined,
                info: packet.info || `${packet.protocol} ${packet.source} → ${packet.destination}`
            };
            console.log('Processed packet:', processedPacket);
            this.packetHandlers.forEach(handler => handler(processedPacket));
        });

        this.socket.on('alert', (alert: Alert) => {
            this.alertHandlers.forEach(handler => handler(alert));
        });

        this.socket.on('stats', (stats: Statistics) => {
            console.log('Socket received stats:', stats);
            // Process stats before forwarding
            const processedStats: Statistics = {
                ...stats,
                totalPackets: stats.totalPackets || 0,
                packetsPerSecond: stats.packetsPerSecond || 0,
                protocolDistribution: stats.protocolDistribution || [],
                activeConnections: stats.activeConnections || 0,
                uniqueHosts: stats.uniqueHosts || 0,
                packetsAnalyzed: stats.packetsAnalyzed || 0,
                alertsGenerated: stats.alertsGenerated || 0,
                totalBytes: stats.totalBytes || 0,
                bytesPerSecond: stats.bytesPerSecond || 0
            };
            this.statsHandlers.forEach(handler => handler(processedStats));
        });

        this.socket.on('capture_status', (status: CaptureStatus) => {
            this.status = status.status;
            this.interface = status.interface;
            this.statusHandlers.forEach(handler => handler(status));
        });

        this.socket.on('connect_error', (error: Error) => {
            this.connectErrorHandlers.forEach(handler => handler(error));
        });

        this.socket.on('disconnect', () => {
            this.status = 'disconnected';
            this.interface = undefined;
            this.statusHandlers.forEach(handler => handler({ status: this.status, interface: this.interface }));
            this.disconnectHandlers.forEach(handler => handler());
        });

        this.socket.on('sudo_required', () => {
            this.sudoRequiredHandlers.forEach(handler => handler());
        });

        this.socket.on('capture_started', (data: { interface?: string }) => {
            this.status = 'running';
            this.interface = data.interface;
            this.statusHandlers.forEach(handler => handler({ status: this.status, interface: this.interface }));
        });

        this.socket.on('capture_stopped', () => {
            this.status = 'stopped';
            this.interface = undefined;
            this.statusHandlers.forEach(handler => handler({ status: this.status, interface: this.interface }));
        });
    }

}

// Export the singleton instance
export const socketService = SocketService.getInstance();
