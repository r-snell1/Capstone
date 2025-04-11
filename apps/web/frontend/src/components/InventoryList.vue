<!--
  web/frontend/src/components/InventoryList.vue

  Author: Ryan Snell
  Date: 15 Mar 2025
  Project: Capstone Project

  Description:
  This component displays the list of inventory items. It fetches the inventory data from the backend API
  and renders the items in a list. The component also allows users to add new inventory items by submitting a form.

  Responsibilities:
  - Fetches inventory data from the backend API using the `getInventory` method.
  - Displays the inventory items in a list format.
  - Handles the addition of new items via a form that includes item name, quantity, and barcode.
  - Updates the list with the newly added item after submission.
-->
<template>
  <div>
    <h1>Inventory List</h1>
    <!-- Render the list of inventory items -->
    <ul>
      <li v-for="item in inventory" :key="item.id">
        {{ item.name }} - Quantity: {{ item.quantity }}
      </li>
    </ul>

    <h2>Add New Item</h2>
    <!-- Form to add new inventory items -->
    <form @submit.prevent="handleAddItem">
      <input v-model="newItem.name" type="text" placeholder="Item name" required />
      <input v-model.number="newItem.quantity" type="number" placeholder="Quantity" required />
      <input v-model="newItem.barcode" type="text" placeholder="Barcode" />
      <button type="submit">Add Item</button>
    </form>

    <!-- Display error message if any -->
    <p v-if="errorMessage" style="color: red;">{{ errorMessage }}</p>
  </div>
</template>

<script>
import { ref, onMounted } from 'vue';
import { getInventory, addInventoryItem } from '../api.js';

export default {
  setup() {
    // Reactive data for inventory items and new item form input
    const inventory = ref([]);
    const newItem = ref({
      name: '',
      quantity: 1,
      barcode: '',
    });
    const errorMessage = ref('');

    // TODO: Replace this with an actual JWT token when implementing authentication
    const token = 'your_jwt_token';

    // Function to fetch inventory data from the backend API with error handling
    const fetchInventory = async () => {
      try {
        // Directly update inventory without using an intermediate variable
        inventory.value = await getInventory(token);
      } catch (error) {
        console.error('Error fetching inventory:', error);
        errorMessage.value = 'Failed to load inventory. Please try again later.';
      }
    };

    // Function to handle adding a new inventory item with error handling
    const handleAddItem = async () => {
      try {
        const addedItem = await addInventoryItem(newItem.value, token); // Add new item
        inventory.value.push(addedItem); // Update inventory with the newly added item
        newItem.value = { name: '', quantity: 1, barcode: '' }; // Reset form fields
      } catch (error) {
        console.error('Error adding item:', error);
        errorMessage.value = 'Failed to add new item. Please try again later.';
      }
    };

    // Fetch inventory data when the component is mounted
    onMounted(fetchInventory);

    // Return data and methods to the template
    return { inventory, newItem, errorMessage, handleAddItem };
  },
};
</script>

<style scoped>
.inventory-list {
  width: 100%;
  max-width: 800px;
  margin: 0 auto;
  padding: 20px;
  background-color: #fff;
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
  border-radius: 8px;
}

h1 {
  text-align: center;
  margin-bottom: 20px;
}

ul {
  list-style-type: none;
  padding: 0;
}

li {
  display: flex;
  justify-content: space-between;
  padding: 10px;
  border-bottom: 1px solid #ccc;
}

button {
  background-color: #dc3545;
  color: white;
  border: none;
  padding: 5px 10px;
  border-radius: 5px;
}

button:hover {
  background-color: #c82333;
}
</style>