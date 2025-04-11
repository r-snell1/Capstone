// backend/src/config/db.js
//
// Ryan Snell
//
// 15 Mar 2025
//
// Capstone Project
//
// Description:
// This file sets up the MongoDB connection using the `mongoose` library. It exports the mongoose object,
// which can be used for interacting with MongoDB through the application. The connection string is loaded from
// environment variables using the `dotenv` package.

require('dotenv').config();
const mongoose = require('mongoose');

// MongoDB connection setup using Mongoose
mongoose.connect(process.env.DATABASE_URL, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connected'))
    .catch((err) => console.error('MongoDB connection error:', err));

module.exports = mongoose;