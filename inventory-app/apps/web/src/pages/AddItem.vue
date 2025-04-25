<template>
  <div class="p-4 max-w-xl mx-auto">
    <h1 class="text-2xl font-bold mb-6 text-gray-800">Add New Item</h1>
    <form @submit.prevent="submitItem" class="space-y-4 bg-white p-6 rounded shadow-md">
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

      <div class="flex justify-end">
        <button
            type="submit"
            class="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700"
        >
          Add Item
        </button>
      </div>
    </form>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { fetchItems, createItem, updateItem, deleteItem } from '@shared/api';

const router = useRouter()

const name = ref('')
const quantity = ref(1)
const location = ref('')
const description = ref('')

const submitItem = async () => {
  const newItem = {
    name: name.value,
    quantity: quantity.value,
    location: location.value,
    description: description.value,
  }

  try {
    await createItem(newItem)
    router.push('/')
  } catch (error) {
    console.error('Error adding item:', error)
    alert('Something went wrong. Please try again.')
  }
}
</script>