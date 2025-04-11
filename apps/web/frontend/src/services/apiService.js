// web/frontend/src/services/apiService.js

import axiosInstance from './axios';  // Adjust the path as needed

const fetchData = () => {
    return axiosInstance.get('/your-api-endpoint');
};

export default { fetchData };