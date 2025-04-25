<template>
  <div class="p-4 max-w-xl mx-auto">
    <h1 class="text-2xl font-bold mb-6 text-gray-800">Edit Item</h1>

    <form @submit.prevent="handleUpdate" class="space-y-4 bg-white p-6 rounded shadow-md">
      <div>
        <label class="block text-gray-700 font-medium mb-1">Name</label>
        <input
            v-model="name"
            type="text"
            required
            class="w-full border border-gray-300 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
      </div>

      <div>
        <label class="block text-gray-700 font-medium mb-1">Quantity</label>
        <input
            v-model.number="quantity"
            type="number"
            min="0"
            required
            class="w-full border border-gray-300 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
      </div>

      <div>
        <label class="block text-gray-700 font-medium mb-1">Location</label>
        <input
            v-model="location"
            type="text"
            class="w-full border border-gray-300 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
        />
      </div>

      <div>
        <label class="block text-gray-700 font-medium mb-1">Description</label>
        <textarea
            v-model="description"
            rows="3"
            class="w-full border border-gray-300 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
        ></textarea>
      </div>

      <div class="flex justify-between">
        <button
            type="button"
            @click="router.push('/')"
            class="bg-gray-400 text-white px-4 py-2 rounded hover:bg-gray-500"
        >
          Cancel
        </button>

        <button
            type="submit"
            class="bg-green-600 text-white px-4 py-2 rounded hover:bg-green-700"
        >
          Save Changes
        </button>

        <button
          type="button"
          @click="handleDelete"
          class="bg-red-600 text-white px-4 py-2 rounded hover:bg-red-700"
        >
          Delete
        </button>
      </div>
    </form>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import axios from 'axios'
import { fetchItems, createItem, updateItem, deleteItem } from '@shared/api';

const lastDeletedItem = ref(null);

const route = useRoute()
const router = useRouter()
const id = route.params.id

const name = ref('')
const quantity = ref(1)
const location = ref('')
const description = ref('')

const fetchItem = async () => {
  try {
    const res = await axios.get(`http://localhost:5050/api/items/${id}`)
    const data = res.data
    name.value = data.name
    quantity.value = data.quantity
    location.value = data.location
    description.value = data.description
  } catch (err) {
    console.error('Error loading item:', err)
    alert('Failed to load item.')
  }
}

const handleUpdate = async () => {
  const updatedItem = {
    name: name.value,
    quantity: quantity.value,
    location: location.value,
    description: description.value,
  }

  try {
    await updateItem(id, updatedItem)
    await router.push('/')
  } catch (err) {
    console.error('Update failed:', err)
    alert('Error updating item. Please try again.')
  }
}

const handleDelete = async () => {
  if (confirm('Are you sure you want to delete this item?')) {
    const deletedItem = {
      name: name.value,
      quantity: quantity.value,
      location: location.value,
      description: description.value,
    };

    try {
      await deleteItem(id);
      lastDeletedItem.value = deletedItem;

      const undo = confirm('Item deleted. Do you want to undo?');
      if (undo) {
        await createItem(deletedItem);
        alert('Item restored.');
      }

      await router.push('/');
    } catch (err) {
      console.error('Delete failed:', err);
      alert('Error deleting item. Please try again.');
    }
  }
};

onMounted(fetchItem)
</script>