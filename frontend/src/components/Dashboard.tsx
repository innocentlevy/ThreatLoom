import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    AppBar,
    Box,
    IconButton,
    Paper,
    Toolbar,
    Typography,
    Switch,
    Button,
    Collapse,
    Pagination,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    Grid,
    Select,
    MenuItem,
    FormControl,
    InputLabel
} from '@mui/material';
import { AlertMapping } from './AlertMapping';
import SecurityIcon from '@mui/icons-material/Security';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import NetworkCheckIcon from '@mui/icons-material/NetworkCheck';
import { socketService } from '../services/socket';
import { PacketTable } from './PacketTable';
import { AlertList } from './AlertList';
import { Statistics } from './Statistics';
import { Packet, Alert } from '../types/index';
import './Dashboard.css';

interface NetworkInterface {
    id: string;
    name: string;
    description: string;
}

interface StatsData {
    totalPackets: number;
    packetsPerSecond: number;
    protocolDistribution: Array<{ name: string; value: number; }>;
}

const Dashboard = () => {
    const navigate = useNavigate();
    const [isCapturing, setIsCapturing] = useState(false);
    const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
    const [selectedInterface, setSelectedInterface] = useState<string>('');
    const [packets, setPackets] = useState<Packet[]>([]);
    const [alerts, setAlerts] = useState<Alert[]>([]);
    const [expandedPackets, setExpandedPackets] = useState(false);
    const [expandedAlerts, setExpandedAlerts] = useState(true);
    const [currentPage, setCurrentPage] = useState(1);
    const [packetsPerPage] = useState(10);
    const [stats, setStats] = useState<StatsData>({
        totalPackets: 0,
        packetsPerSecond: 0,
        protocolDistribution: []
    });
    const [error, setError] = useState<string>('');

    const handleLogout = () => {
        localStorage.removeItem('token');
        socketService.disconnect();
        navigate('/login');
    };


    const fetchInterfaces = async () => {
        try {
            const response = await fetch('http://localhost:5001/api/interfaces');
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const data = await response.json();
            if (data.error) {
                throw new Error(data.error);
            }
            setInterfaces(data.interfaces);
            if (data.interfaces.length > 0 && !selectedInterface) {
                setSelectedInterface(data.interfaces[0].name);
            }
        } catch (error) {
            console.error('Failed to fetch interfaces:', error);
            setError('Failed to fetch network interfaces. Make sure tshark is installed and you have necessary permissions.');
        }
    };

    const handleCaptureToggle = async () => {
        try {
            setError('');
            if (isCapturing) {
                console.log('Stopping capture...');
                await socketService.stopCapture();
            } else {
                if (!selectedInterface) {
                    setError('Please select a network interface');
                    return;
                }
                console.log(`Starting capture on interface ${selectedInterface}...`);
                await socketService.startCapture({ interface: selectedInterface });
            }
        } catch (error) {
            console.error('Failed to toggle capture:', error);
            setError('Failed to toggle packet capture');
        }
    };

    useEffect(() => {
        const token = localStorage.getItem('token');
        if (!token) {
            navigate('/login');
            return;
        }

        try {
            socketService.connect();
            fetchInterfaces();

            const packetHandler = (packet: Packet) => {
                setPackets(prev => [packet, ...prev].slice(0, 100));
            };

            const alertHandler = (alert: Alert) => {
                setAlerts(prev => [alert, ...prev]);
            };

            const statsHandler = (newStats: StatsData) => {
                setStats({
                    totalPackets: newStats.totalPackets || 0,
                    packetsPerSecond: newStats.packetsPerSecond || 0,
                    protocolDistribution: newStats.protocolDistribution || []
                });
            };

            const statusHandler = (status: { status: string, interface?: string }) => {
                setIsCapturing(status.status === 'running');
                if (status.interface) {
                    setSelectedInterface(status.interface);
                }
            };

            socketService.onPacket(packetHandler);
            socketService.onAlert(alertHandler);
            socketService.onStats(statsHandler);
            socketService.onCaptureStatus(statusHandler);

            // Fetch initial data
            socketService.getStats().catch((error: Error) => {
                console.error('Failed to fetch status:', error);
                setError('Failed to fetch initial status');
            });

            return () => {
                socketService.offPacket(packetHandler);
                socketService.offAlert(alertHandler);
                socketService.offStats(statsHandler);
                socketService.offCaptureStatus(statusHandler);
                socketService.disconnect();
            };
        } catch (error) {
            console.error('Socket connection error:', error);
            setError('Failed to connect to server');
            navigate('/login');
        }
    }, [navigate]);

    return (
        <Box sx={{ display: 'flex', flexDirection: 'column', height: '100vh', bgcolor: '#1a1f1a' }}>
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
                                onChange={(e) => setSelectedInterface(e.target.value)}
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
                                    <MenuItem key={iface.id} value={iface.name}>
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
                        <Statistics stats={stats} />
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
                                            {alert.type}
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
                                        {packets
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
                                                <span style={{ color: '#ff4444', fontWeight: 500 }}>{alert.type}</span>
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
