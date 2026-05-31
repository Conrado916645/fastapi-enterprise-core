# 🛡️ FastAPI Enterprise Core

A production-ready, modular FastAPI backend boilerplate featuring Dual-Token JWT Authentication, SQLite with SQLAlchemy, and highly granular Role-Based Access Control (RBAC).

This architecture is designed to be the "spine" of any modern web application, allowing you to easily plug in new modules and scale effortlessly.

## ✨ Features

* **Granular RBAC:** A powerful dependency factory that allows you to lock down endpoints based on specific modules and actions (e.g., `require_permission("speedtester", "create")`).
* **Modular Architecture:** Routes, schemas, and models are strictly separated, allowing you to add new apps/modules in a clean, plug-and-play fashion.
* **Automated Bootstrapping:** Utilizes FastAPI's Lifespan Context Manager to automatically generate a `super_admin` account on the first server boot.
* **Environment Protection:** Secrets are securely managed via `.env` files using `pydantic-settings`.
* **Rate Limiting:** Protects endpoints against brute-force attacks using `slowapi` (e.g., 5 requests/minute on login).
* **CORS Ready:** Pre-configured Middleware to allow seamless connection with frontend frameworks (React, Vue, HTML/JS).
