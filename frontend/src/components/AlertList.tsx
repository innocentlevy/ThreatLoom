import React, { useState } from 'react';
import {
    Box,
    Paper,
    Typography,
    FormControl,
    InputLabel,
    Select,
    MenuItem,
    TextField,
    Chip,
    List,
    ListItem,
    ListItemText,
    IconButton,
    Collapse
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import CloseIcon from '@mui/icons-material/Close';

interface Alert {
    id: string;
    type: string;
    severity: 'high' | 'medium' | 'low';
    message: string;
    details?: string;
    timestamp: string;
}

interface SelectChangeEvent {
    target: {
        value: string;
    };
}

interface AlertListProps {
    alerts: Alert[];
}

const dummyAlerts: Alert[] = [
    {
        id: '1',
        type: 'DDoS Attack',
        severity: 'high',
        message: 'Potential DDoS attack detected',
        details: 'High volume of traffic from IP: 192.168.1.100',
        timestamp: new Date().toISOString()
    },
    {
        id: '2',
        type: 'Port Scan',
        severity: 'medium',
        message: 'Port scanning activity detected',
        details: 'Multiple ports scanned from IP: 192.168.1.101',
        timestamp: new Date().toISOString()
    },
    {
        id: '3',
        severity: 'high',
        message: 'Multiple failed authentication attempts from 172.217.20.46',
        timestamp: '22:47:05',
        type: 'Authentication Failure',
        details: '5 failed login attempts in 1 minute'
    },
    {
        id: '4',
        severity: 'low',
        message: 'DNS request to suspicious domain from 192.168.1.100',
        timestamp: '22:47:00',
        type: 'DNS Request',
        details: 'Request to known malicious domain'
    }
];

const severityColors = {
    low: '#4caf50',
    medium: '#ff9800',
    high: '#f44336',
};

export const AlertList: React.FC<AlertListProps> = ({ alerts }) => {
    const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
    const [searchTerm, setSearchTerm] = useState('');
    const [expandedAlerts, setExpandedAlerts] = useState<string[]>([]);

    const filteredAlerts = (alerts.length > 0 ? alerts : dummyAlerts)
        .filter(alert => 
            selectedSeverity === 'all' || alert.severity === selectedSeverity
        )
        .filter(alert =>
            alert.message.toLowerCase().includes(searchTerm.toLowerCase()) ||
            alert.type.toLowerCase().includes(searchTerm.toLowerCase())
        );

    const toggleExpand = (alertId: string) => {
        setExpandedAlerts((prev: string[]) =>
            prev.includes(alertId)
                ? prev.filter((id: string) => id !== alertId)
                : [...prev, alertId]
        );
    };

    const handleDismiss = (alertId: string) => {
        // TODO: Implement alert dismissal logic
        console.log('Dismissing alert:', alertId);
    };

    const severityCounts = alerts.reduce((acc, alert) => {
        acc[alert.severity] = (acc[alert.severity] || 0) + 1;
        return acc;
    }, {} as Record<string, number>);

    return (
        <Paper sx={{ p: 2, bgcolor: '#1a1f1a', color: '#fff' }}>
            <Box sx={{ mb: 3 }}>
                <Typography variant="h6" sx={{ color: '#4caf50', mb: 2 }}>
                    Security Alerts
                </Typography>
                
                <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
                    <FormControl size="small" sx={{ minWidth: 120 }}>
                        <InputLabel sx={{ color: '#4caf50' }}>Severity</InputLabel>
                        <Select
                            value={selectedSeverity}
                            label="Severity"
                            onChange={(e: SelectChangeEvent) => setSelectedSeverity(e.target.value)}
                            sx={{
                                color: '#fff',
                                '& .MuiOutlinedInput-notchedOutline': {
                                    borderColor: '#4caf50',
                                }
                            }}
                        >
                            <MenuItem value="all">All</MenuItem>
                            <MenuItem value="high">High</MenuItem>
                            <MenuItem value="medium">Medium</MenuItem>
                            <MenuItem value="low">Low</MenuItem>
                        </Select>
                    </FormControl>

                    <TextField
                        size="small"
                        placeholder="Search alerts..."
                        value={searchTerm}
                        onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSearchTerm(e.target.value)}
                        sx={{
                            flexGrow: 1,
                            '& .MuiOutlinedInput-root': {
                                color: '#fff',
                                '& fieldset': { borderColor: '#4caf50' }
                            }
                        }}
                    />
                </Box>

                <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
                    {Object.entries(severityCounts).map(([severity, count]) => (
                        <Chip
                            key={severity}
                            label={`${severity}: ${count}`}
                            color={severity === 'high' ? 'error' : severity === 'medium' ? 'warning' : 'success'}
                            variant={selectedSeverity === severity ? 'filled' : 'outlined'}
                            onClick={() => setSelectedSeverity(severity)}
                            sx={{ textTransform: 'capitalize' }}
                        />
                    ))}
                </Box>
            </Box>

            <List sx={{ maxHeight: 400, overflow: 'auto' }}>
                {filteredAlerts.map((alert) => (
                    <ListItem
                        key={alert.id}
                        sx={{
                            mb: 1,
                            bgcolor: '#2a2f2a',
                            borderRadius: 1,
                            flexDirection: 'column',
                            alignItems: 'stretch'
                        }}
                    >
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                <Chip
                                    label={alert.severity}
                                    color={alert.severity === 'high' ? 'error' : alert.severity === 'medium' ? 'warning' : 'success'}
                                    size="small"
                                />
                                <Typography variant="subtitle2" sx={{ color: '#4caf50' }}>
                                    {alert.type}
                                </Typography>
                            </Box>
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                <Typography variant="caption" sx={{ color: '#888' }}>
                                    {new Date(alert.timestamp).toLocaleString()}
                                </Typography>
                                <IconButton
                                    size="small"
                                    onClick={() => toggleExpand(alert.id)}
                                    sx={{ color: '#4caf50' }}
                                >
                                    {expandedAlerts.includes(alert.id) ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                                </IconButton>
                                <IconButton
                                    size="small"
                                    onClick={() => handleDismiss(alert.id)}
                                    sx={{ color: '#ff6b6b' }}
                                >
                                    <CloseIcon />
                                </IconButton>
                            </Box>
                        </Box>

                        <Collapse in={expandedAlerts.includes(alert.id)} timeout="auto" unmountOnExit>
                            <Box sx={{ mt: 1, pl: 2 }}>
                                <Typography variant="body2" sx={{ mb: 1 }}>
                                    {alert.message}
                                </Typography>
                                {alert.details && (
                                    <Typography variant="caption" sx={{ color: '#888' }}>
                                        {alert.details}
                                    </Typography>
                                )}
                            </Box>
                        </Collapse>
                    </ListItem>
                ))}
            </List>
        </Paper>
    );
};
