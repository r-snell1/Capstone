// backend/src/middlewares/authMiddleware.js
//
// Ryan Snell
//
// 16 Mar 2025

const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';

// Middleware to authenticate JWT tokens and attach the user to the request
const authMiddleware = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');

    if (!token) {
        return res.status(401).json({ message: 'Access denied. No token provided.' });
    }

    try {
        // Verify the token and attach the decoded user data to the request object
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded.user; // Attach the user info to the request
        next();
    } catch (err) {
        console.error('Token verification error:', err);  // Log the error for debugging
        res.status(400).json({ message: 'Invalid or expired token' });
    }
};

// Middleware to check if the user is an admin
const adminMiddleware = (req, res, next) => {
    if (req.user?.role !== 'admin') {
        return res.status(403).json({ message: 'Access forbidden. You are not an admin.' });
    }
    next();
};

// Exporting both middlewares
module.exports = { authMiddleware, adminMiddleware };