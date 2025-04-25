import { createRouter, createWebHistory } from 'vue-router'
import HomePage from '@/pages/HomePage.vue'
import AddItem from '@/pages/AddItem.vue'
import EditItem from '@/pages/EditItem.vue'

const routes = [
    { path: '/', name: 'Home', component: HomePage },
    { path: '/add-item', name: 'AddItem', component: AddItem },
    { path: '/edit-item/:id', name: 'EditItem', component: EditItem, props: true },
]

const router = createRouter({
    history: createWebHistory(),
    routes,
})

export default router