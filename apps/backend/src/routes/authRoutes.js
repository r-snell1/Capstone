// backend/src/routes/authRoutes.js
//
// Ryan Snell
//
// 15 Mar 2025
//
// Capstone Project
//
// Description:
// This file defines routes for authentication, including user login and registration.
// It includes JWT-based authentication for securing routes and user access.

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { authMiddleware, adminMiddleware } = require('../middlewares/authMiddleware');
const User = require('../models/Users');

const router = express.Router();

// JWT Secret (make sure to set this in an environment variable)
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';

// Helper function to create a new user
const createUserInDB = async (username, hashedPassword, role) => {
    const newUser = new User({
        username,
        password: hashedPassword,
        role,
    });

    // Save the user to the database
    await newUser.save();
    return newUser;
};

// 1. **Login** route
router.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    try {
        const user = await User.findOne({ username });

        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const payload = { userId: user._id, role: user.role };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

        res.json({ token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// 2. **Register** route
router.post('/register', async (req, res) => {
    const { username, password, role } = req.body;

    if (!username || !password || !role) {
        return res.status(400).json({ message: 'Username, password, and role are required' });
    }

    try {
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await createUserInDB(username, hashedPassword, role);

        res.status(201).json({ message: 'User created successfully', user: newUser });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to register user' });
    }
});

// 3. **Protected Route** (Example for any route where user authentication is required)
router.get('/protected', authMiddleware, (req, res) => {
    res.status(200).json({ message: 'This is a protected route!' });
});

// 4. **Admin Route** (Only admins can access this route)
router.get('/admin', [authMiddleware, adminMiddleware], (req, res) => {
    res.status(200).json({ message: 'Welcome, admin!' });
});

// 5. **Get All Users** (Admin-only route)
router.get('/users', [authMiddleware, adminMiddleware], async (req, res) => {
    try {
        const users = await User.find();
        res.status(200).json({ users });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to fetch users' });
    }
});

// 6. **Get User Profile** (Authenticated user can access only their own profile)
router.get('/profile', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        res.status(200).json({ user });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to fetch user profile' });
    }
});

module.exports = router;