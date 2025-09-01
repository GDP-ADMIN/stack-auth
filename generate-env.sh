#!/usr/bin/env bash
set -euo pipefail

# ========= Functions =========
gen_password() {
  # Random 16-char password with letters+digits
  LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16 || true
}

gen_key() {
  local prefix=$1
  echo "${prefix}_$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16 || true)"
}

gen_uuid() {
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen | tr '[:upper:]' '[:lower:]'
  else
    python3 -c 'import uuid; print(str(uuid.uuid4()).lower())'
  fi
}

gen_base64url_key() {
  # Generate 32 random bytes and encode as base64url (like jose.base64url.encode)
  head -c 32 /dev/urandom | base64 | tr '/+' '_-' | tr -d '='
}

# ========= Generate Values =========
ADMIN_EMAIL="admin@gdplabs.id"
ADMIN_PASSWORD=$(gen_password)

INTERNAL_PUBLISHABLE_CLIENT_KEY=$(gen_key "pcki")
INTERNAL_SECRET_SERVER_KEY=$(gen_key "ski")
INTERNAL_SUPER_SECRET_ADMIN_KEY=$(gen_key "saki")

PROJECT_ID=$(gen_uuid)

DB_URL="postgresql://postgres:password@localhost:5432/stackframe"

SECRET_SERVER_KEY=$(gen_key "sk")
PUBLISHABLE_CLIENT_KEY=$(gen_key "pck")
SUPER_SECRET_ADMIN_KEY=$(gen_key "sak")

STACK_SERVER_SECRET=$(gen_base64url_key)

BASE_URL="https://stag-api-stackauth-gdplabs-gen-ai-starter.obrol.id"
TRUSTED_DOMAINS="https://chat.gdplabs.id"

# ========= Print Config =========
cat <<EOF
# Stackauth Secret

STACK_SEED_INTERNAL_PROJECT_USER_EMAIL: "$ADMIN_EMAIL"
STACK_SEED_INTERNAL_PROJECT_USER_PASSWORD: "$ADMIN_PASSWORD"
STACK_SEED_INTERNAL_PROJECT_PUBLISHABLE_CLIENT_KEY: "$INTERNAL_PUBLISHABLE_CLIENT_KEY"
STACK_SEED_INTERNAL_PROJECT_SECRET_SERVER_KEY: "$INTERNAL_SECRET_SERVER_KEY"
STACK_SEED_INTERNAL_PROJECT_SUPER_SECRET_ADMIN_KEY: "$INTERNAL_SUPER_SECRET_ADMIN_KEY"

STACK_SERVER_SECRET: "$STACK_SERVER_SECRET"

# Optional: If you want to use Google OAuth, uncomment the following lines or setup in the dashboard
# STACK_GOOGLE_CLIENT_ID: "your-google-client-id"
# STACK_GOOGLE_CLIENT_SECRET: "your-google-client-secret"

# Backend Configmap
STACK_AUTH_BASE_URL: "$BASE_URL"
STACK_AUTH_PROJECT_ID: "$PROJECT_ID"
STACK_AUTH_TRUSTED_DOMAINS: "$TRUSTED_DOMAINS" # FE URL, e.g. https://chat.gdplabs.id

# Backend Secret
STACKAUTH_DB_URL: "$DB_URL"

STACK_AUTH_ADMIN_EMAIL: "$ADMIN_EMAIL"
STACK_AUTH_ADMIN_PASSWORD: "$ADMIN_PASSWORD"

STACK_AUTH_INTERNAL_SECRET_SERVER_KEY: "$INTERNAL_SECRET_SERVER_KEY"
STACK_AUTH_INTERNAL_PUBLISHABLE_CLIENT_KEY: "$INTERNAL_PUBLISHABLE_CLIENT_KEY"
STACK_AUTH_INTERNAL_SUPER_SECRET_ADMIN_KEY: "$INTERNAL_SUPER_SECRET_ADMIN_KEY"

STACK_AUTH_SECRET_SERVER_KEY: "$SECRET_SERVER_KEY"
STACK_AUTH_PUBLISHABLE_CLIENT_KEY: "$PUBLISHABLE_CLIENT_KEY"
STACK_AUTH_SUPER_SECRET_ADMIN_KEY: "$SUPER_SECRET_ADMIN_KEY"

# UI Configmap
NEXT_PUBLIC_STACK_AUTH_PROJECT_ID: "$PROJECT_ID"
NEXT_PUBLIC_STACK_AUTH_BASE_URL: "$BASE_URL"
NEXT_PUBLIC_STACK_AUTH_CLIENT_KEY: "$PUBLISHABLE_CLIENT_KEY"

# UI Secret
STACK_AUTH_SERVER_KEY: "$SECRET_SERVER_KEY"
EOF
