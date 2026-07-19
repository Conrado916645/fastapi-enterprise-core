# app/core/registry.py

# This is the master list of all dynamically installed "apps" in your API.
# If you build a new app, you just type its name here.
APP_REGISTRY = {
    "users": ["read", "create", "update", "delete"],
    "system": ["read", "create", "update", "delete"],
    
}