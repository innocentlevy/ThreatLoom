import React from 'react';
import { Box, Card, CardContent, Typography, Grid } from '@mui/material';
import { Statistics } from '../types';

interface StatsDisplayProps {
    stats: Statistics;
}

const StatsDisplay: React.FC<StatsDisplayProps> = ({ stats }) => {
    return (
        <Box sx={{ mb: 2 }}>
            <Grid container spacing={2}>
                <Grid item xs={12} md={6} lg={3}>
                    <Card>
                        <CardContent>
                            <Typography variant="h6" gutterBottom>
                                Packet Statistics
                            </Typography>
                            <Typography>Total Packets: {stats.totalPackets}</Typography>
                            <Typography>Packets/Second: {stats.packetsPerSecond}</Typography>
                            <Typography>Packets Analyzed: {stats.packetsAnalyzed}</Typography>
                        </CardContent>
                    </Card>
                </Grid>
                <Grid item xs={12} md={6} lg={3}>
                    <Card>
                        <CardContent>
                            <Typography variant="h6" gutterBottom>
                                Network Activity
                            </Typography>
                            <Typography>Total Bytes: {stats.totalBytes}</Typography>
                            <Typography>Bytes/Second: {stats.bytesPerSecond}</Typography>
                            <Typography>Active Connections: {stats.activeConnections}</Typography>
                        </CardContent>
                    </Card>
                </Grid>
                <Grid item xs={12} md={6} lg={3}>
                    <Card>
                        <CardContent>
                            <Typography variant="h6" gutterBottom>
                                Host Information
                            </Typography>
                            <Typography>Unique Hosts: {stats.uniqueHosts}</Typography>
                            <Typography>Alerts Generated: {stats.alertsGenerated}</Typography>
                        </CardContent>
                    </Card>
                </Grid>
                <Grid item xs={12} md={6} lg={3}>
                    <Card>
                        <CardContent>
                            <Typography variant="h6" gutterBottom>
                                Protocol Distribution
                            </Typography>
                            {stats.protocolDistribution.map((protocol, index) => (
                                <Typography key={index}>
                                    {protocol.name}: {protocol.value}
                                </Typography>
                            ))}
                        </CardContent>
                    </Card>
                </Grid>
            </Grid>
        </Box>
    );
};

export default StatsDisplay;
