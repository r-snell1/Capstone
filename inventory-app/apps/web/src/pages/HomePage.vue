<template>
  <div class="p-4 max-w-4xl mx-auto">
    <header class="mb-6">
      <h1 class="text-3xl font-bold text-gray-800">Inventory Dashboard</h1>
      <p class="text-gray-500">Track and manage your inventory in real-time.</p>
    </header>

    <section class="mb-6">
      <div class="flex justify-between items-center mb-4">
        <h2 class="text-xl font-semibold text-gray-700">Items</h2>
        <button
          class="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700"
          @click="goToAddItem"
        >
          + Add Item
        </button>
      </div>

      <table class="min-w-full bg-white border border-gray-200 rounded">
        <thead class="bg-gray-100">
          <tr>
            <th class="text-left py-2 px-4 border-b">Name</th>
            <th class="text-left py-2 px-4 border-b">Quantity</th>
            <th class="text-left py-2 px-4 border-b">Location</th>
            <th class="text-left py-2 px-4 border-b">Description</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="item in items"
            :key="item._id"
            class="hover:bg-gray-50 cursor-pointer"
            @click="openViewModal(item)"
          >
            <td class="py-2 px-4 border-b">{{ item.name }}</td>
            <td class="py-2 px-4 border-b">{{ item.quantity }}</td>
            <td class="py-2 px-4 border-b">{{ item.location || 'N/A' }}</td>
            <td class="py-2 px-4 border-b">{{ item.description || 'N/A' }}</td>
          </tr>
        </tbody>
      </table>
    </section>

    <AddItemModal v-if="showAddModal" @close="showAddModal = false" @refresh="loadItems" />
    <ViewItemModal
      v-if="showViewModal"
      :item="selectedItem"
      @close="showViewModal = false"
      @refresh="loadItems"
    />
  </div>
</template>

<script setup>
import {onMounted, ref} from 'vue'
import AddItemModal from '@/components/AddItemModal.vue'
import ViewItemModal from '@/components/ViewItemModal.vue'
import { fetchItems, createItem, updateItem, deleteItem } from '@shared/api';

const items = ref([])
const showAddModal = ref(false)
const selectedItem = ref(null)
const showViewModal = ref(false)

const loadItems = async () => {
  try {
    const res = await fetchItems();
    items.value = res.data;
  } catch (err) {
    console.error('Failed to fetch items:', err);
  }
};

const goToAddItem = () => {
  showAddModal.value = true
}

const openViewModal = (item) => {
  selectedItem.value = item
  showViewModal.value = true
}

onMounted(loadItems)
</script>