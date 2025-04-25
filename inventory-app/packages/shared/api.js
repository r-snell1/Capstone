// packages/shared/api.js
import axios from 'axios';

export const fetchItems = () => axios.get('http://localhost:5050/api/items');
export const createItem = (data) => axios.post('http://localhost:5050/api/items', data);
export const updateItem = (id, data) => axios.put(`http://localhost:5050/api/items/${id}`, data);
export const deleteItem = (id) => axios.delete(`http://localhost:5050/api/items/${id}`);