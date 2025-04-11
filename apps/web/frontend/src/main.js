// frontend/src/main.js
//
// Ryan Snell
//
// 15 Mar 2025
//
// Capstone Project
//
// Description:
// This file is the entry point for the Vue.js application. It initializes the Vue instance,
// mounts the app to the DOM, and configures the app with required plugins such as Vue Router.
// The file also imports the App.vue component as the root component of the app.

import './Styles/styles.css';
import { createApp } from 'vue';
import App from './App.vue';
import router from './router';
import store from './store';
import axios from 'axios';

// Set Authorization header globally for axios
axios.defaults.headers.common['Authorization'] = `Bearer ${localStorage.getItem('authToken')}`;

const app = createApp(App);

// Use the router plugin
app.use(router);

// Use the store plugin
app.use(store);

// Mount the app to the DOM
app.mount('#app');