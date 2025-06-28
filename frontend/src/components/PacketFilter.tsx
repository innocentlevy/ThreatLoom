import React, { useState } from 'react';
import {
    Box,
    TextField,
    Select,
    MenuItem,
    FormControl,
    InputLabel,
    Button,
    Chip,
    Paper,
    IconButton,
    Typography,
} from '@mui/material';
import FilterListIcon from '@mui/icons-material/FilterList';
import CloseIcon from '@mui/icons-material/Close';

export interface PacketFilter {
    protocol?: string;
    sourceIp?: string;
    destinationIp?: string;
    portRange?: string;
    minPacketSize?: number;
    maxPacketSize?: number;
}

interface PacketFilterProps {
    onFilterChange: (filters: PacketFilter) => void;
}

export const PacketFilterComponent: React.FC<PacketFilterProps> = ({ onFilterChange }) => {
    const [showFilters, setShowFilters] = useState(false);
    const [filters, setFilters] = useState<PacketFilter>({});
    const [activeFilters, setActiveFilters] = useState<string[]>([]);

    const protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'All'];

    const handleFilterChange = (field: keyof PacketFilter, value: any) => {
        const newFilters = { ...filters, [field]: value };
        if (!value) {
            delete newFilters[field];
        }
        setFilters(newFilters);
        onFilterChange(newFilters);
        updateActiveFilters(newFilters);
    };

    const updateActiveFilters = (newFilters: PacketFilter) => {
        const active = Object.entries(newFilters)
            .filter(([_, value]) => value)
            .map(([key, value]) => `${key}: ${value}`);
        setActiveFilters(active);
    };

    const clearFilters = () => {
        setFilters({});
        setActiveFilters([]);
        onFilterChange({});
    };

    const removeFilter = (filterToRemove: string) => {
        const [field] = filterToRemove.split(':');
        const newFilters = { ...filters };
        delete newFilters[field as keyof PacketFilter];
        setFilters(newFilters);
        onFilterChange(newFilters);
        updateActiveFilters(newFilters);
    };

    return (
        <Paper sx={{ p: 2, mb: 2, bgcolor: '#1a1f1a', color: '#fff' }}>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                    <FilterListIcon sx={{ mr: 1, color: '#4caf50' }} />
                    <Typography variant="h6">Packet Filters</Typography>
                </Box>
                <Button
                    variant="outlined"
                    color="primary"
                    onClick={() => setShowFilters(!showFilters)}
                    sx={{ color: '#4caf50', borderColor: '#4caf50' }}
                >
                    {showFilters ? 'Hide Filters' : 'Show Filters'}
                </Button>
            </Box>

            {activeFilters.length > 0 && (
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 2 }}>
                    {activeFilters.map((filter) => (
                        <Chip
                            key={filter}
                            label={filter}
                            onDelete={() => removeFilter(filter)}
                            sx={{
                                bgcolor: '#2a2f2a',
                                color: '#4caf50',
                                '& .MuiChip-deleteIcon': {
                                    color: '#4caf50',
                                }
                            }}
                        />
                    ))}
                    <Button
                        size="small"
                        onClick={clearFilters}
                        sx={{ color: '#ff6b6b' }}
                    >
                        Clear All
                    </Button>
                </Box>
            )}

            {showFilters && (
                <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: { xs: '1fr', md: '1fr 1fr 1fr' } }}>
                    <FormControl fullWidth>
                        <InputLabel id="protocol-label" sx={{ color: '#4caf50' }}>Protocol</InputLabel>
                        <Select
                            labelId="protocol-label"
                            value={filters.protocol || ''}
                            label="Protocol"
                            onChange={(e) => handleFilterChange('protocol', e.target.value)}
                            sx={{
                                color: '#fff',
                                '& .MuiOutlinedInput-notchedOutline': {
                                    borderColor: '#4caf50',
                                }
                            }}
                        >
                            {protocols.map((protocol) => (
                                <MenuItem key={protocol} value={protocol}>{protocol}</MenuItem>
                            ))}
                        </Select>
                    </FormControl>

                    <TextField
                        label="Source IP"
                        value={filters.sourceIp || ''}
                        onChange={(e) => handleFilterChange('sourceIp', e.target.value)}
                        sx={{
                            '& .MuiOutlinedInput-root': {
                                color: '#fff',
                                '& fieldset': {
                                    borderColor: '#4caf50',
                                }
                            },
                            '& .MuiInputLabel-root': {
                                color: '#4caf50',
                            }
                        }}
                    />

                    <TextField
                        label="Destination IP"
                        value={filters.destinationIp || ''}
                        onChange={(e) => handleFilterChange('destinationIp', e.target.value)}
                        sx={{
                            '& .MuiOutlinedInput-root': {
                                color: '#fff',
                                '& fieldset': {
                                    borderColor: '#4caf50',
                                }
                            },
                            '& .MuiInputLabel-root': {
                                color: '#4caf50',
                            }
                        }}
                    />

                    <TextField
                        label="Port Range (e.g., 80-443)"
                        value={filters.portRange || ''}
                        onChange={(e) => handleFilterChange('portRange', e.target.value)}
                        sx={{
                            '& .MuiOutlinedInput-root': {
                                color: '#fff',
                                '& fieldset': {
                                    borderColor: '#4caf50',
                                }
                            },
                            '& .MuiInputLabel-root': {
                                color: '#4caf50',
                            }
                        }}
                    />

                    <TextField
                        label="Min Packet Size (bytes)"
                        type="number"
                        value={filters.minPacketSize || ''}
                        onChange={(e) => handleFilterChange('minPacketSize', e.target.value)}
                        sx={{
                            '& .MuiOutlinedInput-root': {
                                color: '#fff',
                                '& fieldset': {
                                    borderColor: '#4caf50',
                                }
                            },
                            '& .MuiInputLabel-root': {
                                color: '#4caf50',
                            }
                        }}
                    />

                    <TextField
                        label="Max Packet Size (bytes)"
                        type="number"
                        value={filters.maxPacketSize || ''}
                        onChange={(e) => handleFilterChange('maxPacketSize', e.target.value)}
                        sx={{
                            '& .MuiOutlinedInput-root': {
                                color: '#fff',
                                '& fieldset': {
                                    borderColor: '#4caf50',
                                }
                            },
                            '& .MuiInputLabel-root': {
                                color: '#4caf50',
                            }
                        }}
                    />
                </Box>
            )}
        </Paper>
    );
};
