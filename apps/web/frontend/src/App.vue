<!--
  web/frontend/src/App.vue

  Author: Ryan Snell
  Date: 15 Mar 2025
  Project: Capstone Project
  Description: The main entry point for the Inventory App, handling role-based UI rendering.
-->

<template>
  <div class="app-container">
    <InventoryList />

    <div v-if="userRole === 'admin'">
      <AdminPanel />
    </div>
    <div v-else-if="userRole === 'user'">
      <UserDashboard />
    </div>
    <div v-else>
      <p>Loading...</p>
    </div>
  </div>
</template>

<script>
import jwt_decode from 'jwt-decode';
import AdminPanel from './views/AdminPanel.vue';
import UserDashboard from './views/UserDashboard.vue';
import InventoryList from './components/InventoryList.vue';

export default {
  components: {
    AdminPanel,
    UserDashboard,
    InventoryList
  },
  data() {
    return {
      userRole: null,
    };
  },
  created() {
    const token = localStorage.getItem('authToken'); // Ensure consistency in key name
    if (token) {
      try {
        const decoded = jwt_decode(token);
        this.userRole = decoded.role; // Extract role from JWT token
      } catch (error) {
        console.error("Invalid token:", error);
        localStorage.removeItem('authToken'); // Remove invalid token
      }
    }
  },
};
</script>

<style scoped>
/* Scoped styles for the App component */
#app {
  font-family: Arial, sans-serif;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}

main {
  flex: 1;
  padding: 20px;
}
</style>