// web/frontend/src/api/index.js
//
// Ryan Snell
//
// 15 Mar 2025
//
// Capstone Project
//
// Description:
// This file contains utility functions to interact with the backend API of the Inventory App.
// It uses axios to make HTTP requests to the backend, such as fetching and adding inventory items.
// The API endpoints are protected and require an Authorization token for access.

import axios from 'axios';

// Set up axios instance with a base URL and timeout
const api = axios.create({
    baseURL: 'http://localhost:8000/api/',  // Update with your backend API URL
    timeout: 10000,
});

// Add token to headers if available before each request
api.interceptors.request.use((config) => {
    const token = localStorage.getItem('token');
    if (token) {
        config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
}, (error) => {
    return Promise.reject(error);
});

// Function to get inventory from the backend
export const getInventory = async () => {
    try {
        const response = await api.get('inventory/');
        return response.data;
    } catch (error) {
        console.error("Error fetching inventory:", error);
        throw error;
    }
};

// Function to add an inventory item
export const addInventoryItem = async (item) => {
    try {
        const response = await api.post('inventory/', item);
        return response.data;
    } catch (error) {
        console.error("Error adding item:", error);
        throw error;
    }
};

export default api;