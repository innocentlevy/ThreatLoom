import React from 'react';
import './PacketTable.css';

import { Box, Paper, Table, TableBody, TableCell, TableContainer, TableHead, TableRow } from '@mui/material';

interface Packet {
    id: number;
    timestamp: string;
    source: string;
    source_port?: number;
    destination: string;
    destination_port?: number;
    protocol: string;
    length: number;
    info: string;
    flags?: string[];
}

interface PacketTableProps {
    packets: Packet[];
}

const dummyPackets: Packet[] = [
    { 
        id: 1, 
        timestamp: new Date().toLocaleTimeString(), 
        source: '192.168.1.100', 
        source_port: 52431,
        destination: '10.0.0.1', 
        destination_port: 80,
        protocol: 'TCP', 
        length: 64, 
        info: 'Waiting for packets...',
        flags: ['SYN', 'ACK']
    },
    { 
        id: 2, 
        timestamp: '22:47:13', 
        source: '172.217.20.46', 
        source_port: 443,
        destination: '192.168.1.100', 
        destination_port: 59321,
        protocol: 'TLS', 
        length: 1024, 
        info: 'Application Data',
        flags: ['PSH', 'ACK']
    },
];

export const PacketTable: React.FC<PacketTableProps> = ({ packets }) => {
    const displayPackets = packets.length > 0 ? packets : dummyPackets;

    return (
        <Box sx={{ width: '100%', overflowX: 'auto' }}>
            <TableContainer component={Paper}>
                <Table stickyHeader>
                    <TableHead>
                        <TableRow>
                            <TableCell>Time</TableCell>
                            <TableCell>Source</TableCell>
                            <TableCell>Destination</TableCell>
                            <TableCell>Protocol</TableCell>
                            <TableCell>Length</TableCell>
                            <TableCell>Info</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {displayPackets.map((packet) => (
                            <TableRow key={packet.id}>
                                <TableCell>{packet.timestamp}</TableCell>
                                <TableCell>{packet.source}{packet.source_port ? `:${packet.source_port}` : ''}</TableCell>
                                <TableCell>{packet.destination}{packet.destination_port ? `:${packet.destination_port}` : ''}</TableCell>
                                <TableCell>{packet.protocol}</TableCell>
                                <TableCell>{packet.length}</TableCell>
                                <TableCell>{packet.info}</TableCell>
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            </TableContainer>
        </Box>
    );
};
