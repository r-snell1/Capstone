// seed.js
const mongoose = require('mongoose')
const Item = require('./apps/api/models/Item')
require('dotenv').config({ path: './apps/api/.env' })
const MONGO_URI = process.env.MONGO_URI

const items = [
    { name: 'Laptop', quantity: 10, location: 'A1', description: 'MacBook Pro M2' },
    { name: 'Monitor', quantity: 5, location: 'B2', description: 'Dell 24-inch' },
    { name: 'Keyboard', quantity: 20, location: 'C3', description: 'Mechanical RGB' },
    { name: 'Mouse', quantity: 15, location: 'D1', description: 'Logitech wireless' },
    { name: 'Printer', quantity: 3, location: 'E4', description: 'HP LaserJet Pro' }
]

mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
    .then(async () => {
        console.log('Connected to MongoDB')
        await Item.deleteMany({})
        await Item.insertMany(items)
        console.log('Items seeded successfully!')
        process.exit()
    })
    .catch(err => {
        console.error('MongoDB connection error:', err)
        process.exit(1)
    })