// backend/src/models/Inventory.js
//
// Ryan Snell
//
// 15 Mar 2025
//
// Capstone Project
//
// Description:
// This file defines the schema and functionality for managing inventory items in MongoDB.
// It provides functions to interact with the inventory collection, performing CRUD operations on inventory items.

const mongoose = require('mongoose');

// Define the schema for the inventory item
const inventorySchema = new mongoose.Schema({
    name: { type: String, required: true },
    categories: { type: [String], default: [] },
    item: { type: String, required: true },
    count: { type: Number, required: true },
    itemType: { type: String },
    lastUpdated: { type: Date },
    location: { type: String, required: true },
    locationAisle: { type: String, required: true },
    locationShelf: { type: String, required: true },
    itemDescription: { type: String },
    image: { type: String },
    tags: { type: [String], default: [] },
    notes: { type: String },
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // Assuming you have a User model
}, {
    timestamps: true, // Automatically adds createdAt and updatedAt fields
});

// Create a model based on the schema
const Inventory = mongoose.model('Inventory', inventorySchema);

// Responsibilities:
// - Handle CRUD operations on inventory items in the MongoDB database.
// - Ensure validation of the data when adding or updating inventory items.
// - Emit updates using Socket.io when inventory changes.

const InventoryModel = {
    // Create a new inventory item
    async create(newItem) {
        try {
            const inventoryItem = new Inventory(newItem);
            const savedItem = await inventoryItem.save(); // Save to MongoDB
            return savedItem; // Return the created inventory item
        } catch (err) {
            throw new Error('Failed to create inventory item: ' + err.message);
        }
    },

    // Get all inventory items for a specific user
    async getAllByUser(userId) {
        try {
            const inventoryItems = await Inventory.find({ user_id: userId }); // Find items for user
            return inventoryItems; // Return all inventory items for the user
        } catch (err) {
            throw new Error('Failed to fetch inventory items: ' + err.message);
        }
    },

    // Update an existing inventory item
    async update(id, updatedItem) {
        try {
            const updatedInventoryItem = await Inventory.findByIdAndUpdate(id, updatedItem, { new: true }); // Update and return the updated item
            if (!updatedInventoryItem) {
                throw new Error('Inventory item not found');
            }
            return updatedInventoryItem; // Return the updated inventory item
        } catch (err) {
            throw new Error('Failed to update inventory item: ' + err.message);
        }
    },

    // Delete an inventory item
    async delete(id) {
        try {
            const deletedInventoryItem = await Inventory.findByIdAndDelete(id); // Delete and return the deleted item
            if (!deletedInventoryItem) {
                throw new Error('Inventory item not found');
            }
            return deletedInventoryItem; // Return the deleted inventory item
        } catch (err) {
            throw new Error('Failed to delete inventory item: ' + err.message);
        }
    },
};

module.exports = InventoryModel;