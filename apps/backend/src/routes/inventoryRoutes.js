// backend/src/routes/inventoryRoutes.js
//
// Ryan Snell
//
// 15 Mar 2025
//
// Capstone Project
//
// Description:
// This file defines routes for managing inventory items.
// It supports CRUD operations, allowing authenticated users to add, update, retrieve, and delete inventory items.
// Admins are required to perform certain operations like updating and deleting items.

const express = require('express');
const inventoryController = require('../controllers/inventoryController');
const { authMiddleware, adminMiddleware } = require('../middlewares/authMiddleware'); // JWT verification and admin middlewares

const router = express.Router();

// 1. **Create** a new inventory item
// POST /inventory - This route allows authenticated users to create new inventory items.
router.post('/inventory', authMiddleware, inventoryController.createInventoryItem);

// 2. **Read** all inventory items for the authenticated user
// GET /inventory - This route fetches all inventory items associated with the authenticated user.
router.get('/inventory', authMiddleware, inventoryController.getInventoryItems);

// 3. **Update** an inventory item by ID (Admin only)
// PUT /inventory/:id - This route allows an admin user to update an existing inventory item by its ID.
router.put('/inventory/:id', authMiddleware, adminMiddleware, inventoryController.updateInventoryItem);

// 4. **Delete** an inventory item by ID (Admin only)
// DELETE /inventory/:id - This route allows an admin user to delete an inventory item by its ID.
router.delete('/inventory/:id', authMiddleware, adminMiddleware, inventoryController.deleteInventoryItem);

// Export the router to use in the main server file
module.exports = router;