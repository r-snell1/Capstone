// backend/src/models/Users.js
//
// Ryan Snell
//
// 15 Mar 2025
//
// Capstone Project
//
// Description:
// This file defines the schema and functionality for managing users in a MongoDB database.
// It provides functions to interact with the users collection, performing CRUD operations on user data.
// The model uses Mongoose to interact with MongoDB and is designed to be used with the Express backend API.

const mongoose = require('mongoose');
const bcrypt = require('bcrypt'); // Use bcrypt for password hashing

// Define the schema for the User model
const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true, // Ensure usernames are unique
    },
    email: {
        type: String,
        required: true,
        unique: true, // Ensure emails are unique
    },
    password: {
        type: String,
        required: true,
    },
    role: {
        type: String,
        enum: ['admin', 'supervisor', 'employee'], // Define valid roles
        default: 'employee', // Default role is 'employee'
    },
});

// Hash the password before saving a user
userSchema.pre('save', async function(next) {
    if (this.isModified('password')) {
        this.password = await bcrypt.hash(this.password, 10);
    }
    next();
});

// Method to check if the provided password matches the hashed password in the database
userSchema.methods.isValidPassword = async function(password) {
    return await bcrypt.compare(password, this.password);
};

// Create the User model based on the schema
const User = mongoose.model('User', userSchema);



module.exports = User;