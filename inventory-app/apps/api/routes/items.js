const express = require('express');
const router = express.Router();
const Item = require('../models/Item');

// GET all items
router.get('/', async (req, res) => {
    const items = await Item.find();
    res.json(items);
});

// GET a single item by ID
router.get('/:id', async (req, res) => {
    try {
        const item = await Item.findById(req.params.id);
        if (!item) {
            return res.status(404).json({ error: 'Item not found' });
        }
        res.json(item);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch item' });
    }
});

// POST a new item
router.post('/', async (req, res) => {
    try {
        const newItem = new Item(req.body);
        await newItem.save();
        res.status(201).json(newItem);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// DELETE an item
router.delete('/:id', async (req, res) => {
    await Item.findByIdAndDelete(req.params.id);
    res.status(204).end();
});

module.exports = router;