#!/bin/bash
# ==============================================================================
# Wazuh Agent Installer - Unified CI Verification Script
# ==============================================================================
# This script runs all checks executed by the CI runner to help developers
# validate their changes locally before pushing.

set -e

# Color codes for pretty logging
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Ensure script runs from project root
cd "$(dirname "$0")"

log_info "Starting Wazuh Agent Installer local CI checks..."

# ------------------------------------------------------------------------------
# 1. Frontend Checks
# ------------------------------------------------------------------------------
log_info "1. Running frontend formatting check..."
if npm run format:check; then
    log_success "Frontend formatting is correct."
else
    log_error "Frontend formatting errors found! Run 'npm run format' to fix."
    exit 1
fi

log_info "2. Running frontend lint checks..."
if npm run lint; then
    log_success "Frontend lint checks passed."
else
    log_error "Frontend lint checks failed."
    exit 1
fi

log_info "3. Building frontend (TypeScript compile & Vite bundle)..."
if npm run build; then
    log_success "Frontend build successful."
else
    log_error "Frontend build failed."
    exit 1
fi

# ------------------------------------------------------------------------------
# 2. Rust Backend Checks
# ------------------------------------------------------------------------------
log_info "4. Running backend formatting check (cargo fmt)..."
if cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check; then
    log_success "Backend formatting is correct."
else
    log_error "Backend formatting errors found! Run 'cargo fmt --manifest-path src-tauri/Cargo.toml' to fix."
    exit 1
fi

log_info "5. Running backend clippy lint checks..."
if cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --all-features -- -D warnings; then
    log_success "Backend clippy checks passed."
else
    log_error "Backend clippy checks failed."
    exit 1
fi

log_info "6. Building and testing backend..."
if cargo check --manifest-path src-tauri/Cargo.toml; then
    log_success "Backend build check passed."
else
    log_error "Backend build check failed."
    exit 1
fi

log_success "All local CI verification checks passed successfully!"
