// Ryan Snell
//
// 15 Mar 2025
//
// Capstone Project
//
// Description:
//     This file sets up and manages the state of the Vuex store for the application. It handles the authentication
//     state, such as storing and validating the JWT token, managing the user’s role, and keeping track of error
//     messages related to token handling. The store is used to centralize the application’s state and make it
//     accessible to all components.
//
//     Responsibilities:
//  •	State Management:
//       •	The store keeps track of the authentication token and the user’s role (admin or user). It also manages
//          error messages related to token issues or validation failures.
// 	•	Mutations:
//      •	setToken: This mutation sets the JWT token in the state, decodes it to extract the user role, and validates
//          its expiration. If the token is invalid or expired, it clears the token and sets an error message.
//      •	logout: This mutation clears the token and user role from the state and removes the token from localStorage,
//             logging the user out.
//      •	setError: This mutation allows setting custom error messages related to token handling or other issues.
// 	•	Actions:
//      •	login: The action to set the token and update the state when the user logs in.
//      •	logout: The action to clear the authentication token and user role when the user logs out.
//      •	handleError: This action handles and commits custom error messages to the store.
// 	•	Getters:
//      •	isAuthenticated: A getter that checks if the user is authenticated by verifying if the token exists.
//      •	isAdmin: A getter that checks if the logged-in user has an admin role.
//      •	getError: A getter to retrieve any error messages stored in the state.
//
//  •  Error Handling:
//      •  The store includes robust error handling for token parsing. If the token is expired or malformed, it is
//         cleared from the state, and a relevant error message is stored. Additionally, the expiration of the JWT token
//         is checked during the setToken mutation.

import { createStore } from 'vuex';

export default createStore({
    state: {
        token: localStorage.getItem('token') || null, // Token to keep track of logged-in state
        userRole: null, // Initialize userRole
        error: null, // Store error messages
    },
    mutations: {
        setToken(state, token) {
            try {
                if (token) {
                    // Decode the JWT token and check if it's valid
                    const decoded = JSON.parse(atob(token.split('.')[1])); // Decode the JWT payload
                    const currentTime = Math.floor(Date.now() / 1000); // Get current time in seconds

                    if (decoded.exp && decoded.exp < currentTime) {
                        throw new Error('Token has expired.');
                    }

                    state.token = token;
                    state.userRole = decoded.role;
                    localStorage.setItem('token', token);
                } else {
                    throw new Error('Invalid token.');
                }
            } catch (error) {
                state.token = null;
                state.userRole = null;
                state.error = 'Failed to set token. ' + error.message;
                localStorage.removeItem('token');
                throw error; // Re-throw error to allow for further handling if necessary
            }
        },
        logout(state) {
            state.token = null;
            state.userRole = null;
            state.error = null;
            localStorage.removeItem('token');
        },
        setError(state, error) {
            state.error = error;
        }
    },
    actions: {
        login({ commit }, token) {
            try {
                commit('setToken', token);
            } catch (error) {
                commit('setError', error.message);
            }
        },
        logout({ commit }) {
            commit('logout');
        },
        handleError({ commit }, error) {
            commit('setError', error.message);
        },
    },
    getters: {
        isAuthenticated: (state) => !!state.token,
        isAdmin: (state) => state.userRole === 'admin',
        getError: (state) => state.error,
    },
});