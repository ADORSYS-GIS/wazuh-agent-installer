# Development Setup

This guide walks through setting up your local environment, building the application, and running verification checks.

## System Prerequisites

The project requires Node.js, Rust, and platform-specific native GUI development libraries.

### 1. Cross-Platform Core Requirements
- **Node.js**: Version 18.x or higher (LTS recommended)
- **npm**: Version 9.x or higher
- **Rust**: Latest stable toolchain (via [rustup](https://rustup.rs/))
- **Cargo**: Included with Rust

### 2. Platform-Specific System Libraries

#### Linux (Debian / Ubuntu)
```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential \
  curl \
  wget \
  file \
  libssl-dev \
  libwebkit2gtk-4.1-dev \
  libayatana-appindicator3-dev \
  librsvg2-dev \
  libxdo-dev
```

#### macOS
- Install Xcode Command Line Tools:
  ```bash
  xcode-select --install
  ```
- No additional package installations required. WebKit and system frameworks are natively provided by macOS.

#### Windows
- Install [Visual Studio C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) (select "Desktop development with C++").
- Ensure the WebView2 runtime is installed (included by default on Windows 10/11).

## Initial Setup

1. Clone the repository and navigate into the project directory:
   ```bash
   git clone git@github.com:ADORSYS-GIS/wazuh-agent-installer.git
   cd wazuh-agent-installer
   ```

2. Install frontend dependencies:
   ```bash
   npm install
   ```

3. Verify Rust toolchain:
   ```bash
   rustc --version
   cargo --version
   ```

## Running the Application

### Development Mode (with Hot Reload)
Run the application in development mode with hot module replacement (HMR) for the webview frontend:
```bash
npm run tauri dev
```

This starts the Vite development server on port 1420 and launches the native Tauri window. Changes to `src/index.html`, `src/styles.css`, or `src/main.ts` will instantly update the interface. Changes in `src-tauri/` will trigger an automatic incremental Cargo rebuild.

### Production Build
To compile the standalone production binary and application bundles:
```bash
npm run tauri build
```

Compiled packages will be generated under `src-tauri/target/release/bundle/`:
- **Linux**: `.deb` packages and `.AppImage`
- **macOS**: `.app` bundle and `.dmg` installer
- **Windows**: `.msi` and `.exe` installers

## Code Quality and CI Gates

Before submitting changes or opening pull requests, you must run the local verification suite. All checks must pass without warnings or errors.

Run the automated CI script:
```bash
./run-ci.sh
```

The script executes the following sequential stages:
1. **Prettier**: Validates frontend source formatting.
2. **ESLint**: Lints TypeScript files for syntactic and stylistic issues.
3. **TypeScript Compiler (`tsc`)**: Verifies strict typing and interface definitions.
4. **Vite Build**: Ensures frontend assets compile cleanly.
5. **Cargo fmt**: Validates Rust formatting against standard conventions.
6. **Cargo clippy**: Runs the Rust linter with warnings treated as errors (`-D warnings`).
7. **Cargo check**: Validates Rust type-checking and borrow checking.
8. **Cargo test**: Executes all unit tests.

### Individual Commands
You can also run checks individually during iterative development:
```bash
# Frontend
npx prettier --check "src/**/*.{ts,html,css}"
npx eslint src/
npx tsc --noEmit

# Backend
cd src-tauri
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cd ..
```
