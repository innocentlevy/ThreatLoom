import React, { useEffect, useState, KeyboardEvent, ChangeEvent, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    AppBar,
    Box,
    Button,
    Collapse,
    Dialog,
    DialogActions,
    DialogContent,
    DialogContentText,
    DialogTitle,
    FormControl,
    IconButton,
    InputLabel,
    MenuItem,
    Pagination,
    Paper,
    Select,
    SelectChangeEvent,
    Switch,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    TextField,
    Toolbar,
    Typography
} from '@mui/material';
import { AlertMapping } from './AlertMapping';
import SecurityIcon from '@mui/icons-material/Security';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import StopIcon from '@mui/icons-material/Stop';
import WarningIcon from '@mui/icons-material/Warning';
import MapIcon from '@mui/icons-material/Map';
import NetworkCheckIcon from '@mui/icons-material/NetworkCheck';
import { socketService } from '../services/socket';
import { Statistics as StatsComponent } from './Statistics';
import { Packet } from '../models/packet';
import { Alert } from '../models/alert';
import { Statistics } from '../models/statistics';
import './Dashboard.css';

import { NetworkInterfaceData } from '../services/socket';

const Dashboard: React.FC = () => {
    const navigate = useNavigate();
    const [error, setError] = useState<string>('');
    const [interfaces, setInterfaces] = useState<NetworkInterfaceData[]>([]);
    const [selectedInterface, setSelectedInterface] = useState<string>('');
    const [isCapturing, setIsCapturing] = useState<boolean>(false);
    const [packets, setPackets] = useState<Packet[]>([]);
    const [alerts, setAlerts] = useState<Alert[]>([]);
    const [showSudoPrompt, setShowSudoPrompt] = useState<boolean>(false);
    const [sudoPassword, setSudoPassword] = useState<string>('');
    const [expandedPackets, setExpandedPackets] = useState<boolean>(true);
    const [expandedAlerts, setExpandedAlerts] = useState<boolean>(true);
    const [expandedMapping, setExpandedMapping] = useState<boolean>(true);
    const [currentPage, setCurrentPage] = useState<number>(1);
    const [packetsPerPage, setPacketsPerPage] = useState<number>(10);
    interface TransformedStats extends Omit<Statistics, 'protocolDistribution'> {
        protocolDistribution: Array<{ name: string; value: number }>;
    }

    const [stats, setStats] = useState<TransformedStats>({
        totalPackets: 0,
        packetsPerSecond: 0,
        protocolDistribution: [],
        activeConnections: 0,
        uniqueHosts: 0,
        packetsAnalyzed: 0,
        alertsGenerated: 0,
        totalBytes: 0,
        bytesPerSecond: 0
    });


    const handleLogout = () => {
        localStorage.removeItem('token');
        socketService.disconnect();
        navigate('/login');
    };



    const handleCaptureToggle = async () => {
        try {
            setError('');
            if (isCapturing) {
                console.log('Stopping capture...');
                await socketService.stopCapture();
                setPackets([]);
                setStats({
                    totalPackets: 0,
                    packetsPerSecond: 0,
                    protocolDistribution: [],
                    activeConnections: 0,
                    uniqueHosts: 0,
                    packetsAnalyzed: 0,
                    alertsGenerated: 0,
                    totalBytes: 0,
                    bytesPerSecond: 0
                });
            } else {
                if (!selectedInterface) {
                    setError('Please select a network interface');
                    return;
                }
                setSudoPassword('');
                setShowSudoPrompt(true);
            }
        } catch (error) {
            console.error('Failed to toggle capture:', error);
            setError('Failed to toggle packet capture');
        }
    };

    useEffect(() => {
        const setupSocket = async () => {
            try {
                const token = localStorage.getItem('token');
                if (!token) {
                    navigate('/login');
                    return;
                }
                
                // Clear any previous error and state
                setError('');
                setIsCapturing(false);
                setSudoPassword('');
                setShowSudoPrompt(false);

                // Connect to socket
                await socketService.connect();
                console.log('Socket connected successfully');
                
                // Set up event handlers
                socketService.onConnectError((err: Error) => {
                    console.error('Socket connection error:', err);
                    setError(`Failed to connect to server: ${err.message}`);
                });

                socketService.onDisconnect(() => {
                    console.log('Socket disconnected');
                    setIsCapturing(false);
                    setPackets([]);
                    setStats({
                        totalPackets: 0,
                        packetsPerSecond: 0,
                        protocolDistribution: [],
                        activeConnections: 0,
                        uniqueHosts: 0,
                        packetsAnalyzed: 0,
                        alertsGenerated: 0,
                        totalBytes: 0,
                        bytesPerSecond: 0
                    });
                });

                socketService.onInterfaces((networkInterfaces) => {
                    console.log('Received interfaces:', networkInterfaces);
                    setInterfaces(networkInterfaces);
                    if (networkInterfaces.length > 0 && !selectedInterface) {
                        setSelectedInterface(networkInterfaces[0].name);
                    }
                });

                socketService.onPacket((packet) => {
                    console.log('Received packet in Dashboard:', packet);
                    setPackets(prevPackets => {
                        const newPackets = [packet, ...prevPackets];
                        // Keep only the latest 1000 packets
                        const trimmedPackets = newPackets.slice(0, 1000);
                        console.log('Updated packets list, now has:', trimmedPackets.length);
                        return trimmedPackets;
                    });
                    
                    // Update stats immediately for smoother UI updates
                    setStats(prevStats => {
                        const newStats = {
                            ...prevStats,
                            totalPackets: prevStats.totalPackets + 1,
                            packetsPerSecond: Math.max(1, prevStats.packetsPerSecond),
                            totalBytes: prevStats.totalBytes + packet.length,
                            protocolDistribution: updateProtocolDistribution(prevStats.protocolDistribution, packet.protocol)
                        };
                        console.log('Updated stats:', newStats);
                        return newStats;
                    });
                });

                // Helper function to update protocol distribution
                const updateProtocolDistribution = (current: Array<{ name: string; value: number }>, protocol: string) => {
                    const existing = current.find(p => p.name === protocol);
                    if (existing) {
                        return current.map(p => p.name === protocol ? { ...p, value: p.value + 1 } : p);
                    } else {
                        return [...current, { name: protocol, value: 1 }];
                    }
                };

                // Log packet updates
                console.log('Packets state updated, count:', packets.length);

                socketService.onAlert((alert) => {
                    setAlerts(prevAlerts => {
                        const newAlerts = [alert, ...prevAlerts];
                        return newAlerts.slice(0, 100);
                    });
                });

                socketService.onStats((newStats) => {
                    const transformedStats: TransformedStats = {
                        ...newStats,
                        protocolDistribution: newStats.protocolDistribution.map(item => ({
                            name: item.protocol.toUpperCase(),
                            value: item.count
                        }))
                    };
                    setStats(prevStats => ({
                        ...transformedStats,
                        // Preserve real-time counters
                        totalPackets: Math.max(prevStats.totalPackets, transformedStats.totalPackets),
                        packetsPerSecond: transformedStats.packetsPerSecond || prevStats.packetsPerSecond,
                        totalBytes: Math.max(prevStats.totalBytes, transformedStats.totalBytes)
                    }));
                });

                socketService.onStatus(({ status, interface: iface }: { status: string; interface?: string }) => {
                    setIsCapturing(status === 'running');
                    if (iface) {
                        setSelectedInterface(iface);
                    }
                });

                socketService.onSudoRequired(() => {
                    setShowSudoPrompt(true);
                });




                // Fetch interfaces and initial stats
                await socketService.fetchInterfaces();
                await socketService.getStats();
            } catch (error) {
                console.error('Failed to setup socket:', error);
                const errorMessage = error instanceof Error ? error.message : String(error);
                setError(`Failed to connect to server: ${errorMessage}`);
            }
        };

        setupSocket();

        return () => {
            socketService.disconnect();
        };
    }, [navigate, selectedInterface, setError, setIsCapturing, setSudoPassword, setShowSudoPrompt, setPackets, setStats]);

    // Monitor packet updates and update statistics
    useEffect(() => {
        if (packets.length > 0) {
            console.log('Packets state updated, count:', packets.length);
            // Update active connections and unique hosts
            const activeConns = packets.filter(p => p.protocol === 'TCP' && p.flags?.includes('SYN')).length;
            const uniqueHosts = new Set([...packets.map(p => p.source), ...packets.map(p => p.destination)]).size;
            setStats(prev => ({
                ...prev,
                activeConnections: activeConns,
                uniqueHosts: uniqueHosts
            }));
        }
    }, [packets, setStats]);

    const handleSudoSubmit = async () => {
        setError('');
        if (!sudoPassword) {
            setError('Please enter sudo password');
            return;
        }
        if (!selectedInterface) {
            setError('Please select a network interface');
            return;
        }

        try {
            console.log('Starting capture on interface:', selectedInterface);
            // Set up sudo required handler before starting capture
            const handleSudoRequired = () => {
                console.log('Sudo required event received in Dashboard');
                setError('Invalid sudo password');
                setSudoPassword('');
                // Keep the prompt open for retry
                setShowSudoPrompt(true);
            };

            socketService.onSudoRequired(handleSudoRequired);

            await socketService.startCapture({
                interface: selectedInterface,
                sudoPassword: sudoPassword.trim() // Ensure no whitespace
            });

            // Remove the handler after successful capture
            socketService.offSudoRequired(handleSudoRequired);

            console.log('Capture started successfully');
            setSudoPassword('');
            setShowSudoPrompt(false);
            setCurrentPage(1);
            setIsCapturing(true);
        } catch (error) {
            console.error('Capture error:', error);
            const errorMessage = error instanceof Error ? error.message : 'Failed to start capture';
            setError(errorMessage);
            
            if (errorMessage.toLowerCase().includes('password')) {
                setSudoPassword('');
                setShowSudoPrompt(true); // Keep prompt open for password errors
            } else {
                setShowSudoPrompt(false);
            }
        }
    };

    return (
        <Box sx={{ display: 'flex', flexDirection: 'column', height: '100vh', bgcolor: '#1a1f1a' }}>
            <Dialog 
                open={showSudoPrompt} 
                onClose={() => setShowSudoPrompt(false)}
                PaperProps={{
                    sx: {
                        bgcolor: '#2c332c',
                        color: '#e0e0e0',
                        border: '1px solid #4caf50'
                    }
                }}
            >
                <DialogTitle sx={{ color: '#4caf50' }}>Sudo Required</DialogTitle>
                <DialogContent>
                    <DialogContentText sx={{ color: '#e0e0e0', mb: 2 }}>
                        Packet capture requires sudo privileges. Please enter your sudo password:
                    </DialogContentText>
                    <TextField
                        autoFocus
                        margin="dense"
                        label="Sudo Password"
                        type="password"
                        fullWidth
                        value={sudoPassword}
                        onChange={(e: ChangeEvent<HTMLInputElement>) => setSudoPassword(e.target.value)}
                        onKeyPress={(e: KeyboardEvent<HTMLInputElement>) => e.key === 'Enter' && handleSudoSubmit()}
                        sx={{
                            '& .MuiOutlinedInput-root': {
                                color: '#e0e0e0',
                                '& fieldset': { borderColor: '#4caf50' },
                                '&:hover fieldset': { borderColor: '#66bb6a' },
                                '&.Mui-focused fieldset': { borderColor: '#81c784' }
                            },
                            '& .MuiInputLabel-root': {
                                color: '#4caf50',
                                '&.Mui-focused': { color: '#81c784' }
                            }
                        }}
                    />
                </DialogContent>
                <DialogActions>
                    <Button 
                        onClick={() => setShowSudoPrompt(false)} 
                        sx={{ color: '#e0e0e0' }}
                    >
                        Cancel
                    </Button>
                    <Button 
                        onClick={handleSudoSubmit}
                        variant="contained"
                        sx={{
                            bgcolor: '#4caf50',
                            '&:hover': { bgcolor: '#66bb6a' }
                        }}
                    >
                        Submit
                    </Button>
                </DialogActions>
            </Dialog>

            <AppBar position="static" sx={{ bgcolor: '#2c332c', boxShadow: 'none', borderBottom: '1px solid #3c443c' }}>
                <Toolbar>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <SecurityIcon sx={{ color: '#4caf50', fontSize: 28 }} />
                        <Typography variant="h6" sx={{ color: '#e0e0e0', fontWeight: 500 }}>
                            ThreatLoom
                        </Typography>
                    </Box>
                    <Box sx={{ flexGrow: 1 }} />
                    {error ? (
                        <Typography color="error" sx={{ mr: 2, fontSize: '0.875rem' }}>
                            {error}
                        </Typography>
                    ) : null}
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                        <FormControl size="small" sx={{ minWidth: 200 }}>
                            <InputLabel id="interface-select-label" sx={{ color: '#e0e0e0' }}>Network Interface</InputLabel>
                            <Select
                                labelId="interface-select-label"
                                value={selectedInterface}
                                onChange={(e: SelectChangeEvent<string>) => setSelectedInterface(e.target.value)}
                                disabled={isCapturing}
                                label="Network Interface"
                                sx={{
                                    color: '#e0e0e0',
                                    '.MuiOutlinedInput-notchedOutline': {
                                        borderColor: '#3c443c'
                                    },
                                    '&:hover .MuiOutlinedInput-notchedOutline': {
                                        borderColor: '#4caf50'
                                    },
                                    '&.Mui-focused .MuiOutlinedInput-notchedOutline': {
                                        borderColor: '#4caf50'
                                    }
                                }}
                            >
                                {interfaces.map((iface) => (
                                    <MenuItem key={iface.name} value={iface.name}>
                                        {iface.name} {iface.description ? `(${iface.description})` : ''}
                                    </MenuItem>
                                ))}
                            </Select>
                        </FormControl>
                        
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                            <Switch
                                checked={isCapturing}
                                onChange={handleCaptureToggle}
                                color="success"
                                size="small"
                            />
                            <Typography
                                variant="body1"
                                sx={{
                                    mr: 2,
                                    minWidth: 80
                                }}
                            >
                                {isCapturing ? `Capturing on ${selectedInterface}` : 'Start Capture'}
                            </Typography>
                            <Button
                                onClick={handleLogout}
                                size="small"
                                sx={{
                                    minWidth: 'auto',
                                    padding: '2px 8px',
                                    fontSize: '0.75rem',
                                    color: '#e0e0e0',
                                    '&:hover': { bgcolor: '#3c443c' }
                                }}
                            >
                                Logout
                            </Button>
                        </Box>
                    </Box>
                </Toolbar>
            </AppBar>

            <Box sx={{ p: 2, display: 'flex', gap: 2, flex: 1 }}>
                {/* Left Panel - Statistics and Summary */}
                <Box sx={{ width: '30%', display: 'flex', flexDirection: 'column', gap: 2 }}>
                    {/* Statistics */}
                    <Paper elevation={0} sx={{ p: 2, bgcolor: '#2c332c', border: '1px solid #3c443c', color: '#e0e0e0' }}>
                        <StatsComponent stats={stats} />
                    </Paper>

                    {/* Network Summary */}
                    <Paper elevation={0} sx={{ p: 2, bgcolor: '#2c332c', border: '1px solid #3c443c', color: '#e0e0e0' }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                            <NetworkCheckIcon sx={{ color: '#4caf50' }} />
                            <Typography variant="subtitle1" sx={{ fontWeight: 500, color: '#4caf50' }}>
                                Network Summary
                            </Typography>
                        </Box>

                        <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2, mb: 3 }}>
                            <Box>
                                <Typography variant="body2" sx={{ color: '#808080', mb: 0.5 }}>
                                    Active Connections
                                </Typography>
                                <Typography variant="h6" sx={{ color: '#e0e0e0' }}>
                                    {packets?.filter(p => p.protocol === 'TCP' && p.flags?.includes('SYN'))?.length || 0}
                                </Typography>
                            </Box>
                            <Box>
                                <Typography variant="body2" sx={{ color: '#808080', mb: 0.5 }}>
                                    Unique IPs
                                </Typography>
                                <Typography variant="h6" sx={{ color: '#e0e0e0' }}>
                                    {new Set([...packets.map(p => p.source), ...packets.map(p => p.destination)]).size}
                                </Typography>
                            </Box>
                        </Box>

                        {/* Recent Activity */}
                        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                            {/* Recent Alerts Summary */}
                            <Box>
                                <Typography variant="body2" sx={{ color: '#e0e0e0', mb: 1 }}>
                                    Recent Alerts: {alerts.length}
                                </Typography>
                                {alerts.slice(-3).map((alert, index) => (
                                    <Box 
                                        key={index} 
                                        sx={{ 
                                            p: 1, 
                                            mb: 0.5, 
                                            bgcolor: '#1a1f1a',
                                            borderLeft: '3px solid #ff4444',
                                            borderRadius: '2px'
                                        }}
                                    >
                                        <Typography variant="caption" sx={{ color: '#ff4444', display: 'block' }}>
                                            {alert.severity.toUpperCase()}: {alert.message}
                                        </Typography>
                                    </Box>
                                ))}
                            </Box>

                            {/* Recent Packets Summary */}
                            <Box>
                                <Typography variant="body2" sx={{ color: '#e0e0e0', mb: 1 }}>
                                    Recent Packets: {packets.length}
                                </Typography>
                                <Box sx={{ 
                                    display: 'flex', 
                                    flexDirection: 'column',
                                    gap: 0.5
                                }}>
                                    {packets.slice(-3).map((packet, index) => (
                                        <Box 
                                            key={index}
                                            sx={{ 
                                                p: 1, 
                                                bgcolor: '#1a1f1a',
                                                borderRadius: '2px',
                                                fontSize: '0.75rem',
                                                color: '#808080'
                                            }}
                                        >
                                            {packet.protocol} | {packet.source} → {packet.destination}
                                        </Box>
                                    ))}
                                </Box>
                            </Box>
                        </Box>
                    </Paper>
                </Box>

                {/* Right Panel - Network Activity, Alerts, and Alert Mapping */}
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, flex: 1, overflow: 'auto' }}>
                    {/* Network Activity */}
                    <Paper elevation={0} sx={{ p: 2, bgcolor: '#2c332c', border: '1px solid #3c443c', color: '#e0e0e0' }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                            <Typography variant="h6">Network Activity</Typography>
                            <IconButton 
                                onClick={() => setExpandedPackets(!expandedPackets)}
                                sx={{ color: '#e0e0e0' }}
                            >
                                {expandedPackets ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                            </IconButton>
                        </Box>

                        <Collapse in={expandedPackets}>
                            <TableContainer sx={{ maxHeight: '400px' }}>
                                <Table size="small" stickyHeader>
                                    <TableHead>
                                        <TableRow>
                                            <TableCell sx={{ bgcolor: '#1a1f1a', color: '#e0e0e0', fontWeight: 500 }}>Time</TableCell>
                                            <TableCell sx={{ bgcolor: '#1a1f1a', color: '#e0e0e0', fontWeight: 500 }}>Source</TableCell>
                                            <TableCell sx={{ bgcolor: '#1a1f1a', color: '#e0e0e0', fontWeight: 500 }}>Destination</TableCell>
                                            <TableCell sx={{ bgcolor: '#1a1f1a', color: '#e0e0e0', fontWeight: 500 }}>Protocol</TableCell>
                                            <TableCell sx={{ bgcolor: '#1a1f1a', color: '#e0e0e0', fontWeight: 500 }}>Info</TableCell>
                                        </TableRow>
                                    </TableHead>
                                    <TableBody>
                                        {packets.length === 0 ? (
                                            <TableRow>
                                                <TableCell colSpan={5} sx={{ textAlign: 'center', color: '#808080' }}>
                                                    No packets captured yet. Start capture to see network activity.
                                                </TableCell>
                                            </TableRow>
                                        ) : packets
                                            .slice((currentPage - 1) * packetsPerPage, currentPage * packetsPerPage)
                                            .map((packet, index) => (
                                            <TableRow 
                                                key={index} 
                                                sx={{ 
                                                    '&:nth-of-type(odd)': { bgcolor: '#1a1f1a' },
                                                    '&:hover': { bgcolor: '#2c332c' }
                                                }}
                                            >
                                                <TableCell sx={{ color: '#e0e0e0' }}>
                                                    {new Date(packet.timestamp).toLocaleTimeString()}
                                                </TableCell>
                                                <TableCell sx={{ color: '#e0e0e0' }}>
                                                    {`${packet.source}${packet.source_port ? `:${packet.source_port}` : ''}`}
                                                </TableCell>
                                                <TableCell sx={{ color: '#e0e0e0' }}>
                                                    {`${packet.destination}${packet.destination_port ? `:${packet.destination_port}` : ''}`}
                                                </TableCell>
                                                <TableCell sx={{ color: '#4caf50' }}>
                                                    {packet.protocol}
                                                </TableCell>
                                                <TableCell 
                                                    sx={{ 
                                                        color: '#808080',
                                                        maxWidth: '300px',
                                                        overflow: 'hidden',
                                                        textOverflow: 'ellipsis',
                                                        whiteSpace: 'nowrap'
                                                    }}
                                                >
                                                    {packet.info}
                                                </TableCell>
                                            </TableRow>
                                        ))}
                                    </TableBody>
                                </Table>
                            </TableContainer>
                            <Box sx={{ display: 'flex', justifyContent: 'center', mt: 2 }}>
                                <Pagination 
                                    count={Math.ceil(packets.length / packetsPerPage)} 
                                    page={currentPage}
                                    onChange={(_event: React.ChangeEvent<unknown>, page: number) => setCurrentPage(page)}
                                    sx={{ 
                                        '& .MuiPaginationItem-root': { 
                                            color: '#e0e0e0',
                                            '&.Mui-selected': { bgcolor: '#4caf50' }
                                        } 
                                    }}
                                />
                            </Box>
                        </Collapse>

                        {!expandedPackets && packets.length > 0 && (
                            <Typography variant="body2" sx={{ color: '#808080' }}>
                                {packets.length} packets captured. Click to expand.
                            </Typography>
                        )}
                    </Paper>

                    {/* Security Alerts */}
                    <Paper elevation={0} sx={{ p: 2, bgcolor: '#2c332c', border: '1px solid #3c443c', color: '#e0e0e0' }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                            <Typography variant="h6">Security Alerts</Typography>
                            <IconButton 
                                onClick={() => setExpandedAlerts(!expandedAlerts)}
                                sx={{ color: '#e0e0e0' }}
                            >
                                {expandedAlerts ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                            </IconButton>
                        </Box>

                        <Collapse in={expandedAlerts}>
                            <Box sx={{ maxHeight: '300px', overflow: 'auto' }}>
                                {alerts.map((alert, index) => (
                                    <Box 
                                        key={index} 
                                        sx={{ 
                                            mb: 1, 
                                            p: 2, 
                                            bgcolor: '#1a1f1a', 
                                            borderRadius: 1,
                                            borderLeft: '4px solid #ff4444',
                                            '&:hover': { bgcolor: '#2c332c' }
                                        }}
                                    >
                                        <Typography 
                                            variant="body2" 
                                            sx={{ 
                                                display: 'flex',
                                                flexDirection: 'column',
                                                gap: 0.5
                                            }}
                                        >
                                            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                                <span style={{ color: '#ff4444', fontWeight: 500 }}>{alert.severity.toUpperCase()}</span>
                                                <span style={{ color: '#808080', fontSize: '0.8rem' }}>
                                                    {new Date(alert.timestamp).toLocaleTimeString()}
                                                </span>
                                            </Box>
                                            <span style={{ color: '#e0e0e0' }}>{alert.message}</span>
                                        </Typography>
                                    </Box>
                                ))}
                            </Box>
                        </Collapse>

                        {!expandedAlerts && alerts.length > 0 && (
                            <Typography variant="body2" sx={{ color: '#808080' }}>
                                {alerts.length} alerts detected. Click to expand.
                            </Typography>
                        )}
                    </Paper>

                    {/* Alert Mapping */}
                    <Paper elevation={0} sx={{ p: 2, bgcolor: '#2c332c', border: '1px solid #3c443c', color: '#e0e0e0' }}>
                        <AlertMapping />
                    </Paper>
                </Box>
            </Box>
        </Box>
    );
};

export default Dashboard;
