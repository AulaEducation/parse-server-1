# Parse Server

## Cusom Role configs

- Add the following to `config.json`. Role can be string ("read"), or array (["read", "write"])

```
"auth": {
  "roles": {
    "UBPost": {
      "visitor": "read",
      "student": "read",
      "instructor": ["read", "write"]
    },
    "UBComment": {
      "student": "read",
      "instructor": ["read", "write"]
    },
    "UBClassRoom": {
      "visitor": "read",
      "student": "read",
      "instructor": ["read", "write"]
    },
    "UBClassRoomMaterialModule": {
      "student": "read",
      "instructor": ["read", "write"]
    },
    "UBClassRoomMaterialOrder": {
      "student": "read",
      "instructor": ["read", "write"]
    },
    "UBClassRoomPost": {
      "student": ["read", "write"],
      "instructor": ["read", "write"]
    }
  }
}
```
