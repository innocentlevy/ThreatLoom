import React, { useState, useEffect } from 'react';
import {
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Typography,
  Box
} from '@mui/material';
import { Alert } from '../types';
import { socketService } from '../services/socket';

interface AlertMap {
  [ip: string]: {
    lastAlert: Alert;
    alertCount: number;
    types: Set<string>;
  }
}

export const AlertMapping: React.FC = () => {
  const [alertMap, setAlertMap] = useState<AlertMap>({});

  useEffect(() => {
    // Subscribe to security alerts
    const unsubscribe = socketService.onAlert((alert: Alert) => {
      const sourceIp = extractIpFromAlert(alert);
      if (sourceIp) {
        setAlertMap(prevMap => {
          const newMap = { ...prevMap };
          if (!newMap[sourceIp]) {
            newMap[sourceIp] = {
              lastAlert: alert,
              alertCount: 0,
              types: new Set()
            };
          }
          newMap[sourceIp].lastAlert = alert;
          newMap[sourceIp].alertCount++;
          newMap[sourceIp].types.add(alert.type);
          return newMap;
        });
      }
    });

    return () => {
      unsubscribe();
    };
  }, []);

  const extractIpFromAlert = (alert: Alert): string | null => {
    // Extract IP from alert details or message using regex
    const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/;
    const match = alert.details.match(ipRegex) || alert.message.match(ipRegex);
    return match ? match[0] : null;
  };

  return (
    <Box sx={{ width: '100%', mt: 2 }}>
      <Typography variant="h6" gutterBottom component="div">
        Real-time Alert Mapping
      </Typography>
      <TableContainer component={Paper}>
        <Table sx={{ minWidth: 650 }} aria-label="alert mapping table">
          <TableHead>
            <TableRow>
              <TableCell>Source IP</TableCell>
              <TableCell>Alert Count</TableCell>
              <TableCell>Alert Types</TableCell>
              <TableCell>Last Alert</TableCell>
              <TableCell>Last Seen</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {Object.entries(alertMap).map(([ip, data]) => (
              <TableRow
                key={ip}
                sx={{
                  '&:last-child td, &:last-child th': { border: 0 },
                  backgroundColor: data.lastAlert.severity === 'high' 
                    ? 'rgba(244, 67, 54, 0.1)' 
                    : data.lastAlert.severity === 'medium'
                    ? 'rgba(255, 152, 0, 0.1)'
                    : 'inherit'
                }}
              >
                <TableCell component="th" scope="row">
                  {ip}
                </TableCell>
                <TableCell>{data.alertCount}</TableCell>
                <TableCell>{Array.from(data.types).join(', ')}</TableCell>
                <TableCell>{data.lastAlert.message}</TableCell>
                <TableCell>
                  {new Date(data.lastAlert.timestamp).toLocaleTimeString()}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
};
