// server.js
//
// Ryan A. Snell
//
// 15 Mar 2025
//
// Capstone Project
//
// Description:
// This file sets up the backend server for the Inventory App using Node.js and Express.
// It handles the HTTP requests, including routes for fetching and adding inventory items.
// Socket.io is used to manage real-time communication between the server and the frontend.
// The server also includes middlewares for handling CORS and authentication tokens.
// Graceful shutdown logic is included to handle cleanup on server termination.

const express = require('express');
const cors = require('cors');
const http = require(''); // TODO: add the http
const socketIo = require('socket.io');
const jwt = require('jsonwebtoken');

// Import routes
const authRoutes = require('./src/routes/authRoutes');
const inventoryRoutes = require('./src/routes/inventoryRoutes');

// Import MongoDB connection
require('./src/config/db');

const app = express();
app.use(cors());
app.use(express.json()); // Middleware for JSON parsing

// Use the authentication and inventory routes
app.use('/api/auth', authRoutes);
app.use('/api/inventory', inventoryRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack); // Log the error
    res.status(500).json({ message: 'Something went wrong!' });
});

const server = http.createServer(app);
const io = socketIo(server, {
    cors: { origin: "*" }
});

const helmet = require('helmet');
const {connection} = require("./src/config/db");
app.use(helmet());

// Socket.io JWT Authentication Middleware
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (token) {
        jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
            if (err) return next(new Error('Authentication error'));
            socket.user = decoded; // Store user info on socket
            next();
        });
    } else {
        next(new Error('Authentication error'));
    }
});

// WebSocket connection handler
io.on('connection', (socket) => {
    console.log('New client connected');

    // You can broadcast inventory updates to clients here
    socket.on('createInventoryItem', (item) => {
        io.emit('inventoryUpdated', { type: 'create', item });
    });

    socket.on('updateInventoryItem', (item) => {
        io.emit('inventoryUpdated', { type: 'update', item });
    });

    socket.on('deleteInventoryItem', (itemId) => {
        io.emit('inventoryUpdated', { type: 'delete', itemId });
    });

    socket.on('disconnect', () => {
        console.log('Client disconnected');
    });
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// Graceful shutdown logic for MongoDB and Socket.io
process.on('SIGINT', async () => {
    console.log('Gracefully shutting down the server...');

    // Close MongoDB connection
    try {
        await connection.close(); // Close MongoDB connection
        console.log('MongoDB connection closed.');
    } catch (err) {
        console.error('Error closing MongoDB connection:', err);
    }

    // Close WebSocket server
    io.close(() => {
        console.log('Socket.io server closed.');
    });

    // Shut down the server
    server.close(() => {
        console.log('HTTP server closed.');
        process.exit(0); // Exit process
    });
});

// Export io for use in routes
module.exports = { app, io };