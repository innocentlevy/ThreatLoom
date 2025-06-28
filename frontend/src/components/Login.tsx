import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    Box,
    Button,
    Container,
    Paper,
    TextField,
    Typography
} from '@mui/material';
import SecurityIcon from '@mui/icons-material/Security';
import authService from '../services/auth';
import './Login.css';

export const Login: React.FC = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError('');
        console.log('Attempting login...');

        try {
            console.log('Calling authService.login...');
            const success = await authService.login(username, password);
            console.log('Login result:', success);
            
            if (success) {
                console.log('Login successful, navigating to dashboard...');
                navigate('/dashboard');
            } else {
                console.log('Login failed, setting error message...');
                setError('Invalid username or password');
            }
        } catch (err) {
            console.error('Login error:', err);
            setError('Failed to connect to server. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <Box sx={{ 
            minHeight: '100vh', 
            display: 'flex', 
            alignItems: 'center', 
            bgcolor: '#1a1f1a'
        }}>
            <Container maxWidth="xs">
                <Paper 
                    elevation={0} 
                    sx={{ 
                        p: 4, 
                        bgcolor: '#2c332c',
                        border: '1px solid #3c443c'
                    }}
                >
                    <Box sx={{ mb: 4, textAlign: 'center' }}>
                        <SecurityIcon sx={{ color: '#4caf50', fontSize: 40, mb: 2 }} />
                        <Typography variant="h5" component="h1" sx={{ color: '#e0e0e0', fontWeight: 500 }}>
                            ThreatLoom
                        </Typography>
                        <Typography variant="subtitle1" sx={{ color: '#808080', mt: 1 }}>
                           Security Information and Event Managemnt System
                        </Typography>
                    </Box>

                    <form onSubmit={handleSubmit}>
                        <TextField
                            margin="normal"
                            required
                            fullWidth
                            id="username"
                            label="Username"
                            name="username"
                            autoComplete="username"
                            autoFocus
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            error={!!error}
                            sx={{
                                '& .MuiOutlinedInput-root': {
                                    '& fieldset': {
                                        borderColor: '#3c443c',
                                    },
                                    '&:hover fieldset': {
                                        borderColor: '#4caf50',
                                    },
                                    '&.Mui-focused fieldset': {
                                        borderColor: '#4caf50',
                                    },
                                },
                                '& .MuiInputLabel-root': {
                                    color: '#808080',
                                },
                                '& .MuiOutlinedInput-input': {
                                    color: '#e0e0e0',
                                },
                            }}
                        />
                        <TextField
                            margin="normal"
                            required
                            fullWidth
                            name="password"
                            label="Password"
                            type="password"
                            id="password"
                            autoComplete="current-password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            error={!!error}
                            helperText={error}
                            sx={{
                                '& .MuiOutlinedInput-root': {
                                    '& fieldset': {
                                        borderColor: '#3c443c',
                                    },
                                    '&:hover fieldset': {
                                        borderColor: '#4caf50',
                                    },
                                    '&.Mui-focused fieldset': {
                                        borderColor: '#4caf50',
                                    },
                                },
                                '& .MuiInputLabel-root': {
                                    color: '#808080',
                                },
                                '& .MuiOutlinedInput-input': {
                                    color: '#e0e0e0',
                                },
                                '& .MuiFormHelperText-root': {
                                    color: '#f44336',
                                },
                            }}
                        />
                        <Button
                            type="submit"
                            fullWidth
                            variant="contained"
                            sx={{ 
                                mt: 3, 
                                mb: 2, 
                                bgcolor: '#4caf50',
                                '&:hover': {
                                    bgcolor: '#45a049'
                                }
                            }}
                            disabled={loading}
                        >
                            {loading ? 'Signing in...' : 'Sign In'}
                        </Button>
                    </form>
                </Paper>
            </Container>
        </Box>
    );
};

export default Login;
