import React from 'react';
import { Box, Grid, Paper, Typography } from '@mui/material';
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts';

interface Protocol {
    name: string;
    value: number;
}

interface StatsType {
    totalPackets: number;
    packetsPerSecond: number;
    protocolDistribution: Protocol[];
}

const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042'];

export const Statistics: React.FC<{ stats: StatsType }> = ({ stats }) => {
    const totalPackets = stats?.totalPackets ?? 0;
    const packetsPerSecond = stats?.packetsPerSecond ?? 0;
    const protocolData = stats?.protocolDistribution?.map((protocol: Protocol) => ({
        name: protocol.name || 'Unknown',
        value: protocol.value || 0
    })) || [];

    return (
        <Box sx={{ width: '100%', p: 2 }}>
            <Typography variant="h6" sx={{ mb: 2, color: '#4caf50' }}>
                Network Statistics
            </Typography>
            
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', md: '1fr 1fr' }, gap: 2 }}>
                    <Paper elevation={0} sx={{ p: 2, bgcolor: '#1a1f1a', borderRadius: 1 }}>
                        <Typography variant="body2" color="textSecondary">
                            Total Packets
                        </Typography>
                        <Typography variant="h4" sx={{ color: '#4caf50', mt: 1 }}>
                            {totalPackets.toLocaleString()}
                        </Typography>
                    </Paper>

                    <Paper elevation={0} sx={{ p: 2, bgcolor: '#1a1f1a', borderRadius: 1 }}>
                        <Typography variant="body2" color="textSecondary">
                            Packets/Second
                        </Typography>
                        <Typography variant="h4" sx={{ color: '#4caf50', mt: 1 }}>
                            {packetsPerSecond.toFixed(1)}
                        </Typography>
                    </Paper>
                </Box>

                {protocolData.length > 0 && (
                    <Paper elevation={0} sx={{ p: 2, bgcolor: '#1a1f1a', borderRadius: 1 }}>
                        <Typography variant="body2" color="textSecondary" sx={{ mb: 2 }}>
                            Protocol Distribution
                        </Typography>
                        <Box sx={{ height: 300, display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
                            <ResponsiveContainer width="100%" height="100%">
                                <PieChart>
                                    <Pie
                                        data={protocolData}
                                        dataKey="value"
                                        nameKey="name"
                                        cx="50%"
                                        cy="50%"
                                        outerRadius={80}
                                        fill="#4caf50"
                                    >
                                        {protocolData.map((entry, index) => (
                                            <Cell 
                                                key={`cell-${index}`} 
                                                fill={COLORS[index % COLORS.length]} 
                                            />
                                        ))}
                                    </Pie>
                                    <Tooltip />
                                    <Legend />
                                </PieChart>
                            </ResponsiveContainer>
                        </Box>
                    </Paper>
                )}
            </Box>
        </Box>
    );
};
