// backend/src/controllers/inventoryController.js
//
// Ryan Snell
//
// 15 Mar 2025
//
// Capstone Project
//
// Description:
// This file defines the routes and logic for managing inventory items in the backend.
// It provides functionality to perform CRUD (Create, Read, Update, Delete) operations on inventory items,
// allowing users to interact with their inventory in a secure and authenticated manner.
// It also emits updates to clients through Socket.io when inventory is modified.

const express = require('express');
const router = express.Router();
const Inventory = require('../models/Inventory'); // Assuming you have an Inventory model for MongoDB
const authMiddleware = require('../middlewares/authMiddleware');
const socketIo = require('socket.io');
const io = socketIo();

// CRUD Operations

// 1. **Create** new inventory item
router.post('/inventory', authMiddleware, async (req, res) => {
    const {
        name,
        categories, // Array of categories
        item,
        count,
        itemType,
        lastUpdated,
        location,
        locationAisle,
        locationShelf,
        itemDescription,
        image,
        tags,
        notes
    } = req.body;

    // Validation (simplified, can be expanded)
    if (!name || !item || !count || !location || !locationAisle || !locationShelf) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    try {
        // Create a new inventory item in MongoDB
        const newInventoryItem = new Inventory({
            name,
            categories,
            item,
            count,
            itemType,
            lastUpdated,
            location,
            locationAisle,
            locationShelf,
            itemDescription,
            image,
            tags,
            notes
        });

        // Save the inventory item
        const savedItem = await newInventoryItem.save();

        // Emit real-time update to all connected clients
        io.emit('inventoryUpdate', savedItem);
        res.status(201).json(savedItem);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to add inventory item' });
    }
});

// 2. **Read** all inventory items (filtered by user)
router.get('/inventory', authMiddleware, async (req, res) => {
    const userId = req.user.id; // Assuming user ID is stored in the token

    try {
        // Find all inventory items for the user
        const inventoryItems = await Inventory.find({ user_id: userId });

        res.status(200).json(inventoryItems);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch inventory items' });
    }
});

// 3. **Update** an inventory item
router.put('/inventory/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    const {
        name,
        categories, // Array of categories
        item,
        count,
        itemType,
        lastUpdated,
        location,
        locationAisle,
        locationShelf,
        itemDescription,
        image,
        tags,
        notes
    } = req.body;

    // Authorization check: only admins can update inventory items
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'You do not have permission to update inventory items' });
    }

    try {
        // Find the inventory item and update it
        const updatedItem = await Inventory.findByIdAndUpdate(
            id,
            {
                name,
                categories,
                item,
                count,
                itemType,
                lastUpdated,
                location,
                locationAisle,
                locationShelf,
                itemDescription,
                image,
                tags,
                notes
            },
            { new: true } // Return the updated item
        );

        if (!updatedItem) {
            return res.status(404).json({ error: 'Inventory item not found' });
        }

        // Emit real-time update to all connected clients
        io.emit('inventoryUpdate', updatedItem);
        res.status(200).json(updatedItem);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to update inventory item' });
    }
});

// 4. **Delete** an inventory item
router.delete('/inventory/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;

    // Authorization check: only admins can delete inventory items
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'You do not have permission to delete inventory items' });
    }

    try {
        // Find and delete the inventory item
        const deletedItem = await Inventory.findByIdAndDelete(id);

        if (!deletedItem) {
            return res.status(404).json({ error: 'Inventory item not found' });
        }

        // Emit real-time update to all connected clients
        io.emit('inventoryUpdate', deletedItem);
        res.status(200).json({ message: 'Inventory item deleted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to delete inventory item' });
    }
});

// Export the router
module.exports = router;