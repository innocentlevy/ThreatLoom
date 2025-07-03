export interface Packet {
    id: string;
    timestamp: number;
    source: string;
    source_port?: number;
    destination: string;
    destination_port?: number;
    protocol: string;
    length: number;
    payload?: string;
    flags?: string[];
    info?: string;
}
