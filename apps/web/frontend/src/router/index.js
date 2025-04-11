// web/frontend/src/router/index.js
//
// Ryan Snell
//
// 15 Mar 2025
//
// Capstone Project
//

import { createRouter, createWebHistory } from 'vue-router';
import AdminPanel from '../Views/AdminPanel.vue';
import UserDashboard from '../Views/UserDashboard.vue';
import LoginPage from '../Views/Login.vue';
import ProtectedPage from '../components/Protected.vue';
import jwt_decode from 'jwt-decode';

const routes = [
    {
        path: '/admin',
        component: AdminPanel,
        beforeEnter: (to, from, next) => {
            const token = localStorage.getItem('authToken');
            if (token) {
                try {
                    const decoded = jwt_decode(token);
                    if (decoded.role === 'admin') {
                        next();
                    } else {
                        next('/'); // Redirect if not admin
                    }
                } catch (error) {
                    next('/login');
                }
            } else {
                next('/login');
            }
        },
    },
    {
        path: '/user-dashboard',
        component: UserDashboard,
        beforeEnter: (to, from, next) => {
            const token = localStorage.getItem('authToken');
            if (token) {
                try {
                    const decoded = jwt_decode(token);
                    if (decoded.role === 'user' || decoded.role === 'admin') {
                        next();
                    } else {
                        next('/');
                    }
                } catch (error) {
                    next('/login');
                }
            } else {
                next('/login');
            }
        },
    },
    {
        path: '/protected',
        component: ProtectedPage,
        beforeEnter: (to, from, next) => {
            const token = localStorage.getItem('authToken');
            if (!token) {
                next('/login'); // Redirect if no token
                return;
            }

            try {
                jwt_decode(token); // Verify token
                next(); // Allow access
            } catch (error) {
                localStorage.removeItem('authToken'); // Remove invalid token
                next('/login'); // Redirect to login
            }
        }
    },
    {
        path: '/login',
        component: LoginPage,
    },
];

const router = createRouter({
    history: createWebHistory(import.meta.env.BASE_URL),
    routes,
});

// Global guard (optional)
router.beforeEach((to, from, next) => {
    const token = localStorage.getItem('authToken');
    if (to.path !== '/login' && !token) {
        next('/login');
    } else {
        next();
    }
});

export default router;