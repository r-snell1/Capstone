// backend/src/controllers/authController.js
//
// Ryan Snell
//
// 15 Mar 2025
//
// Capstone Project
//
// Description:
// This controller handles user authentication, including login and registration.
// It validates user credentials, generates JWT tokens, and securely manages user authentication.

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { validationResult } = require('express-validator');
const User = require('../models/Users');

const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret";

// Register a new user
const register = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { username, password, email, role } = req.body;

    try {
        const userExists = await User.findOne({ username });
        if (userExists) return res.status(400).json({ error: "Username already taken" });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, email, password: hashedPassword, role });

        await newUser.save();
        res.status(201).json({ message: "User registered successfully" });
    } catch (err) {
        res.status(500).json({ error: "Server error: " + err.message });
    }
};

// Login a user
const login = async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(401).json({ message: 'Invalid credentials' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

        // Generate JWT token
        const token = jwt.sign(
            { id: user._id, role: user.role },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: "Server error: " + err.message });
    }
};

module.exports = { register, login };