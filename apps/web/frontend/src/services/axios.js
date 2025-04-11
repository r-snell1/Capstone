// web/frontend/src/services/axios.js

import axios from 'axios';

const axiosInstance = axios.create({
    baseURL: 'https://your-api-url.com',  // replace with your API base URL
});

// Set the Authorization header for this specific instance
axiosInstance.defaults.headers.common['Authorization'] = `Bearer ${localStorage.getItem('authToken')}`;

export default axiosInstance;