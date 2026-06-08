# Contributing to Wazuh Agent Installer

Thank you for contributing to the Wazuh Agent Installer project! This document outlines the process for getting the project running locally and submitting changes.

## Prerequisites & Dependencies

To work on this project, ensure you have the following installed:

- **Node.js**: LTS version (18+)
- **Rust**: Stable toolchain (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- **System Dependencies**:
  - **Linux**: `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `libsoup-3.0-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev`
  - **macOS**: Xcode Command Line Tools (`xcode-select --install`)

## Getting Started

1. **Clone the repository**
   ```bash
   git clone https://github.com/ADORSYS-GIS/wazuh-agent-installer.git
   cd wazuh-agent-installer
   ```

2. **Install frontend dependencies**
   ```bash
   npm install
   ```

3. **Run the development server (hot-reload)**
   ```bash
   npm run tauri dev
   ```

## Development Workflow

- All UI and branding configuration should be made in `src/config.ts`.
- The UI uses vanilla HTML/TS with a sidebar navigation layout in `src/index.html` and `src/main.ts`.
- The Rust backend is in `src-tauri/src/lib.rs` and manages privileges using `sudo -S` locally instead of `pkexec`.

## Submitting Pull Requests

Before pushing any changes, you **must** run the local CI script. It ensures code formatting, linting, and compilation succeed.

```bash
./run-ci.sh
```

### PR Checklist

1. Ensure `./run-ci.sh` passes completely with no errors or warnings.
2. Use standardized branch names:
   - `feat/` for new features (e.g., `feat/add-new-scanner`)
   - `fix/` for bugfixes (e.g., `fix/sudo-retry-logic`)
   - `chore/` for maintenance (e.g., `chore/update-dependencies`)
3. Provide a clear and concise PR description explaining the changes made and any manual testing steps needed.

Thank you for helping us keep this project clean and stable!
