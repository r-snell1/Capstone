```mermaid
classDiagram

    class API {
        +getInventory(): Promise
        +addInventoryItem(item: Object): Promise
    }

    class InventoryList {
        -inventory: Array
        -newItem: Object
        -errorMessage: String
        +fetchInventory(): void
        +handleAddItem(): void
    }

    class Protected {
        -isAuthenticated: Boolean
        +checkAuthentication(): void
    }

    class Router {
        +routes: Array
        +beforeEnter(): void
    }

    class APIService {
        +fetchData(): Promise
    }

    class AxiosInstance {
        +baseURL: String
        +defaults: Object
    }

    class VuexStore {
        -token: String
        -userRole: String
        -error: String
        +setToken(token: String): void
        +logout(): void
        +setError(error: String): void
        +login(token: String): void
        +handleError(error: String): void
        +isAuthenticated(): Boolean
        +isAdmin(): Boolean
        +getError(): String
    }

    API <|-- APIService
    APIService --> AxiosInstance
    InventoryList --> API : Uses
    Protected --> API : Uses
    Router --> Protected : Navigates to
    Router --> InventoryList : Navigates to
    VuexStore --> Router : Guards routes