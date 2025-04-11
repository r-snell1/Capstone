```mermaid
classDiagram

    class User {
        -String username
        -String email
        -String password
        -String role
        +isValidPassword(password: String): Boolean
    }

    class Inventory {
        -String name
        -List<String> categories
        -String item
        -int count
        -String itemType
        -Date lastUpdated
        -String location
        -String locationAisle
        -String locationShelf
        -String itemDescription
        -String image
        -List<String> tags
        -String notes
        -ObjectId user_id
    }

    class InventoryModel {
        +create(newItem: Inventory): Inventory
        +getAllByUser(userId: ObjectId): List<Inventory>
        +update(id: ObjectId, updatedItem: Inventory): Inventory
        +delete(id: ObjectId): Inventory
    }

    class AuthController {
        +register(req: Request, res: Response): void
        +login(req: Request, res: Response): void
    }

    class InventoryController {
        +create(req: Request, res: Response): void
        +read(req: Request, res: Response): void
        +update(req: Request, res: Response): void
        +delete(req: Request, res: Response): void
    }

    class AuthMiddleware {
        +authMiddleware(req: Request, res: Response, next: Function): void
        +adminMiddleware(req: Request, res: Response, next: Function): void
    }

    class Database {
        +connect(): void
    }

    User "1" -- "*" Inventory : owns >
    User <|-- AuthController : manages >
    InventoryModel <|-- InventoryController : interacts >
    AuthMiddleware <|-- AuthController : secures >
    AuthMiddleware <|-- InventoryController : secures >
    Database <|-- User : connects >
    Database <|-- Inventory : connects >