<!--
  web/frontend/src/components/Login.vue

  Author: Ryan Snell
  Date: 15 Mar 2025
  Project: Capstone Project
  Description: This component handles the user login process, including rendering a form to collect username and password,
               submitting the credentials for authentication, and redirecting the user upon successful login.
-->
<template>
  <div>
    <h1>Login</h1>
    <form @submit.prevent="handleLogin">
      <div>
        <label for="username">Username:</label>
        <input type="text" id="username" v-model="username" placeholder="Username" required />
      </div>
      <div>
        <label for="password">Password:</label>
        <input type="password" id="password" v-model="password" placeholder="Password" required />
      </div>
      <button type="submit">Login</button>
    </form>
    <div v-if="errorMessage" style="color: red;">{{ errorMessage }}</div>
  </div>
</template>

<script>
import axios from 'axios';
import jwt_decode from 'jwt-decode';
import { useRouter } from 'vue-router';
import {ref} from "vue";  // Import useRouter hook

export default {
  setup() {
    const router = useRouter();  // Use useRouter hook to access the router instance

    const username = ref('');  // Using ref for reactive variables
    const password = ref('');
    const errorMessage = ref('');

    const handleLogin = async () => {
      try {
        // Send login request to backend
        const response = await axios.post('/api/login', {
          username: username.value,
          password: password.value,
        });

        const token = response.data.token;
        // Decode the token to extract user role
        const decoded = jwt_decode(token);
        const userRole = decoded.role;

        // Save token to localStorage
        localStorage.setItem('token', token);

        // Set the Authorization header for all future axios requests
        axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;

        // Redirect user based on role
        if (userRole === 'admin') {
          await router.push('/admin');  // Admin redirects to admin panel
        } else {
          await router.push('/user-dashboard');  // Regular user redirects to dashboard
        }

        // Reset form after successful login
        username.value = '';
        password.value = '';
      } catch (error) {
        if (error.response) {
          // Handle server-side error
          if (error.response.status === 401) {
            errorMessage.value = 'Invalid credentials. Please check your username and password.';
          } else {
            errorMessage.value = 'An error occurred. Please try again later.';
          }
        } else {
          // Handle network error
          errorMessage.value = 'Network error. Please check your internet connection.';
        }
        console.error('Login failed:', error);
      }
    };

    return { username, password, errorMessage, handleLogin };  // Return variables and methods to template
  },
};
</script>

<style scoped>
form {
  display: flex;
  flex-direction: column;
  width: 300px;
  margin: 0 auto;
}

form input {
  margin: 5px 0;
  padding: 8px;
  border: 1px solid #ccc;
  border-radius: 4px;
}

form button {
  padding: 8px;
  margin-top: 10px;
  border: none;
  background-color: #4CAF50;
  color: white;
  border-radius: 4px;
  cursor: pointer;
}

form button:hover {
  background-color: #45a049;
}

div {
  margin-top: 10px;
}
</style>