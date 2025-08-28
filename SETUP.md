# 🚀 Stackauth Setup Guide

This document explains how to configure and run **Stackauth**, along with the Backend (BE) and Frontend (FE).

---

## 1. Configure Environment Variables

First, generate the environment variables using the provided script:

```bash
./generate-env.sh
````

This will output a config file with:

* Admin credentials
* Internal project API keys
* Project ID (UUID)
* Secret/publishable keys

> ⚠️ **Important:** Save this file securely. It contains sensitive values such as admin passwords and API keys.

---

## 2. Configure OAuth (Optional)

If you are using OAuth providers (Google, GitHub, Discord, etc.), you need to configure the **redirect URI** in the provider's developer console.

Format:

```
{STACKAUTH_API}/api/v1/auth/oauth/callback/{provider}
```

Example for **Google**:

```
https://stag-api-stackauth-gdplabs-gen-ai-starter.obrol.id/api/v1/auth/oauth/callback/google
```

👉 Replace:

* `{STACKAUTH_API}` with your Stackauth API base URL
* `{provider}` with the OAuth provider name (`google`, `github`, `discord`, etc.)

---

## 3. Run Stackauth

Start the **Stackauth service**:

On startup, Stackauth will:

* Run database migrations
* Seed the **admin user**
* Initialize **internal API keys** (`pcki_`, `ski_`, `saki_`)

---

## 4. Run Backend (BE)

Start the backend service:

On startup, the backend will:

* Initialize the **project setup**
* Generate **API keys** (`pck_`, `sk_`, `sak_`)
* Run database migrations for users

---

## 5. Run Frontend (FE)

The frontend will:

* Use the **Project ID** and **Publishable Client Key** from your environment configuration
* Connect to the Backend and Stackauth services

---

## ✅ Summary

1. Generate env → `./generate-env.sh`
2. Setup OAuth redirect URIs (if using OAuth)
3. Run Stackauth → seeds admin user + internal API keys
4. Run Backend → initializes project + generates API keys + migrates users
5. Run Frontend → connects to BE & Stackauth
