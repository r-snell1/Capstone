<!--
  Protected.vue
  -----------------
  Author: Ryan Snell
  Date: 15 Mar 2025
  Project: Capstone Project
  Description: This component displays protected content that can only be accessed by authenticated users.
-->

<template>
  <div v-if="isAuthenticated" class="protected-container">
    <h2>Protected Content</h2>
    <p>Welcome! This content is only accessible if you're authenticated.</p>
  </div>
</template>

<script>
import { ref, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import api from '../api';

export default {
  setup() {
    const router = useRouter();
    const isAuthenticated = ref(false);

    onMounted(async () => {
      const token = localStorage.getItem('authToken');

      if (!token) {
        console.warn("No authentication token found. Redirecting to login.");
        router.push('/login');
        return;
      }

      try {
        await api.get('/protected', {
          headers: { Authorization: `Bearer ${token}` }
        });

        isAuthenticated.value = true; // Set authentication state to true
      } catch (err) {
        console.error("Access denied:", err);
        localStorage.removeItem('authToken'); // Remove invalid token
        router.push('/login');
      }
    });

    return { isAuthenticated };
  },
};
</script>

<style scoped>
.protected-container {
  text-align: center;
  margin-top: 20px;
}
</style>