import React from 'react';
import { Box, Grid, Paper, Typography } from '@mui/material';
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts';

interface Protocol {
    name: string;
    value: number;
    percentage?: string;
}

interface StatsType {
    // Network statistics interface
    totalPackets: number;
    packetsPerSecond: number;
    protocolDistribution: Protocol[];
    activeConnections: number;
    uniqueHosts: number;
    packetsAnalyzed: number;
    alertsGenerated: number;
    totalBytes: number;
    bytesPerSecond: number;
}

const COLORS = ['#4caf50', '#2196f3', '#ff9800', '#f44336', '#9c27b0'];

export const Statistics: React.FC<{ stats: StatsType }> = ({ stats }) => {
    const totalPackets = stats.totalPackets || 0;
    const packetsPerSecond = stats.packetsPerSecond || 0;
    const protocolData = stats.protocolDistribution
        .filter(protocol => protocol.value > 0)
        .sort((a, b) => b.value - a.value) // Sort by value descending
        .map(protocol => {
            const percentage = ((protocol.value / (totalPackets || 1)) * 100).toFixed(1);
            return {
                name: protocol.name === 'other' ? 'OTHER' : protocol.name.toUpperCase(),
                value: protocol.value,
                percentage
            };
        });

    // If no protocols, show empty state
    if (protocolData.length === 0) {
        protocolData.push({ name: 'No Data', value: 1, percentage: '100.0' });
    }

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
                                        innerRadius={0}
                                        outerRadius={120}
                                        fill="#4caf50"
                                        paddingAngle={2}
                                        label={({ name, value, percentage }) => `${name} (${percentage}%)`}
                                        labelLine={false}
                                        animationBegin={0}
                                        animationDuration={800}
                                        isAnimationActive={true}
                                    >
                                        {protocolData.map((entry, index) => (
                                            <Cell 
                                                key={`cell-${index}`} 
                                                fill={COLORS[index % COLORS.length]} 
                                            />
                                        ))}
                                    </Pie>
                                    <Tooltip 
                                        formatter={(value, name, entry) => [
                                            `${value.toLocaleString()} packets (${entry.payload.percentage}%)`,
                                            name
                                        ]}
                                        contentStyle={{
                                            backgroundColor: '#1a1f1a',
                                            border: '1px solid #4caf50',
                                            borderRadius: '4px',
                                            color: '#fff'
                                        }}
                                    />
                                    <Legend />
                                </PieChart>
                            </ResponsiveContainer>
                        </Box>
                    </Paper>
            </Box>
        </Box>
    );
};
