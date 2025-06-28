import { io, Socket } from 'socket.io-client';
import { Packet, Alert, Statistics } from '../types/index';

class SocketService {
    private socket: Socket | null = null;
    private packetHandlers: ((packet: Packet) => void)[] = [];
    private alertHandlers: ((alert: Alert) => void)[] = [];
    private statsHandlers: ((stats: Statistics) => void)[] = [];
    private statusHandlers: ((status: { status: string, interface?: string }) => void)[] = [];

    connect() {
        if (!this.socket) {
            console.log('Attempting to connect to SIEM server...');
            this.socket = io('http://localhost:5001', {
                transports: ['websocket', 'polling'],
                reconnection: true,
                reconnectionAttempts: 5
            });

            this.socket.on('connect', () => {
                console.log('Connected to SIEM server');
            });

            this.socket.on('connect_error', (error) => {
                console.error('Socket connection error:', error);
            });

            this.socket.on('disconnect', () => {
                console.log('Disconnected from SIEM server');
            });

            this.socket.on('packet_captured', (packet: Packet) => {
                this.packetHandlers.forEach(handler => handler(packet));
            });

            this.socket.on('security_alert', (alert: Alert) => {
                this.alertHandlers.forEach(handler => handler(alert));
            });

            this.socket.on('statistics_update', (stats: Statistics) => {
                this.statsHandlers.forEach(handler => handler(stats));
            });

            this.socket.on('capture_status', (status: { status: string, interface?: string }) => {
                console.log('Received capture status:', status);
                this.statusHandlers.forEach(handler => handler(status));
            });
        }
    }

    disconnect() {
        if (this.socket) {
            this.socket.disconnect();
            this.socket = null;
        }
    }

    startCapture(options?: { interface?: string }): Promise<void> {
        return new Promise((resolve, reject) => {
            if (!this.socket) {
                reject(new Error('Not connected'));
                return;
            }

            // Set a timeout for the response
            const timeoutId = setTimeout(() => {
                this.socket?.off('capture_started');
                this.socket?.off('capture_error');
                reject(new Error('Start capture timeout - no response received'));
            }, 10000); // 10 second timeout

            // Listen for success response
            this.socket.once('capture_started', () => {
                clearTimeout(timeoutId);
                resolve();
            });

            // Listen for error response
            this.socket.once('capture_error', (error: any) => {
                clearTimeout(timeoutId);
                reject(new Error(error.message || 'Failed to start capture'));
            });

            // Emit start capture command with interface option
            console.log('Emitting start_capture event with options:', options);
            this.socket.emit('start_capture', options);
        });
    }

    stopCapture(): Promise<void> {
        return new Promise((resolve, reject) => {
            if (!this.socket) {
                reject(new Error('Not connected'));
                return;
            }

            // Set a timeout for the response
            const timeoutId = setTimeout(() => {
                this.socket?.off('capture_stopped');
                this.socket?.off('capture_error');
                reject(new Error('Stop capture timeout - no response received'));
            }, 10000); // 10 second timeout

            // Listen for success response
            this.socket.once('capture_stopped', () => {
                clearTimeout(timeoutId);
                resolve();
            });

            // Listen for error response
            this.socket.once('capture_error', (error: any) => {
                clearTimeout(timeoutId);
                reject(new Error(error.message || 'Failed to stop capture'));
            });

            // Emit stop capture command
            this.socket.emit('stop_capture');
        });
    }

    onPacket(handler: (packet: Packet) => void) {
        this.packetHandlers.push(handler);
        return () => {
            this.packetHandlers = this.packetHandlers.filter(h => h !== handler);
        };
    }

    offPacket(handler: (packet: Packet) => void) {
        this.packetHandlers = this.packetHandlers.filter(h => h !== handler);
    }

    onAlert(handler: (alert: Alert) => void) {
        this.alertHandlers.push(handler);
        return () => {
            this.alertHandlers = this.alertHandlers.filter(h => h !== handler);
        };
    }

    offAlert(handler: (alert: Alert) => void) {
        this.alertHandlers = this.alertHandlers.filter(h => h !== handler);
    }

    onStats(handler: (stats: Statistics) => void) {
        this.statsHandlers.push(handler);
        return () => {
            this.statsHandlers = this.statsHandlers.filter(h => h !== handler);
        };
    }

    offStats(handler: (stats: Statistics) => void) {
        this.statsHandlers = this.statsHandlers.filter(h => h !== handler);
    }

    onCaptureStatus(handler: (status: { status: string, interface?: string }) => void) {
        this.statusHandlers.push(handler);
        return () => {
            this.statusHandlers = this.statusHandlers.filter(h => h !== handler);
        };
    }

    offCaptureStatus(handler: (status: { status: string, interface?: string }) => void) {
        this.statusHandlers = this.statusHandlers.filter(h => h !== handler);
    }

    getStats(): Promise<void> {
        return new Promise((resolve, reject) => {
            if (!this.socket) {
                reject(new Error('Not connected'));
                return;
            }

            this.socket.emit('get_stats', (response: any) => {
                if (response.status === 'success') {
                    resolve();
                } else {
                    reject(new Error(response.message));
                }
            });
        });
    }
}

export const socketService = new SocketService();
