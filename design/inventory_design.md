
# Inventory App Design Document

## 1. System Architecture Overview

```plaintext
+-------------+     HTTP     +-------------+     Mongoose    +-------------+
| Vue.js Web  |  <------->   |  Express.js |  <----------->  |  MongoDB    |
| React Native|              |    API      |                 |             |
+-------------+              +-------------+                 +-------------+
        ^                         ^                                 
        | Axios                  | CORS, JSON                     
        |                         |
        +----- Shared Logic ------+
              (e.g., @shared/api)

```

## 2. Use Case Diagram

- **Actor**: User
- **Use Cases**:
    - Add Item
    - View Items
    - Edit Item
    - Delete Item

## 3. Class Diagram

### Item Model

- `Item`
  - `String name`
  - `Number quantity`
  - `String location`
  - `String description`
  - `Date createdAt`
  - `Date updatedAt`

## 4. Sequence Diagram - Add Item

```plaintext
User -> Web/Mobile App: Click "Add Item"
Web/Mobile App -> Express API: POST /api/items
Express API -> MongoDB: Save Item
MongoDB -> Express API: Item Saved
Express API -> Web/Mobile App: 201 Created + Item
```

## 5. API Documentation

### Base URL: `/api/items`

| Method | Endpoint        | Description       | Request Body                 | Response         |
|--------|------------------|-------------------|------------------------------|------------------|
| GET    | `/api/items`     | List all items    | N/A                          | `[Item]`         |
| POST   | `/api/items`     | Create new item   | `{ name, quantity, location, description }` | `Item` |
| PUT    | `/api/items/:id` | Update an item    | `{ name?, quantity?, location?, description? }` | `Item` |
| DELETE | `/api/items/:id` | Delete an item    | N/A                          | 204 No Content   |

## 6. MongoDB Schema (Mongoose)

```js
const itemSchema = new mongoose.Schema({
  name: String,
  quantity: Number,
  location: String,
  description: String,
}, { timestamps: true });
```

## 7. Component Tree

### Vue.js Web

```plaintext
App.vue
├── HomePage.vue
│   ├── ItemList.vue
│   ├── AddItemModal.vue
│   └── EditItemModal.vue
```

### React Native

```plaintext
App.js
├── HomePage.js
├── AddItem.js
└── EditItem.js
```

## 8. Navigation Flow

### Web (Vue Router)
- `/` → HomePage → List of Items
- `/edit/:id` → Edit Item

### Mobile (React Navigation)
- `HomePage` (default screen)
- `AddItem` → Add Item screen
- `EditItem` → Edit Item screen with form pre-filled
