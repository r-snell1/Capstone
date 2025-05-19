const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config({ path: __dirname + '/.env' });

const app = express();
const PORT = process.env.PORT || 5055;

const allowedOrigins = ['https://yellow-meadow-055e2b510.6.azurestaticapps.net']

// Middleware
app.use(cors({
  origin: allowedOrigins,
  credentials: true // if you use cookies or auth
}));
app.use(express.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB connected'))
    .catch((err) => console.error(err));

// Routes
app.use('/api/items', require('./routes/items'));

// Root Route
app.get('/', (req, res) => {
    res.json({ message: 'API is working!' });
});

// Start server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
