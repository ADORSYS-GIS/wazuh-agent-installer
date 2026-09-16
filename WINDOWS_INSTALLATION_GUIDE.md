# Wazuh Agent Installer — Windows Setup & Enrollment Guide

Welcome! The **Wazuh Agent Installer** is a desktop application designed to securely install, configure, and connect your Windows machine to our central security monitoring platform.

Follow the step-by-step instructions below to complete installation and enrollment.

---

## Prerequisites

Before starting the installation process, ensure that:

- You have **Administrator rights** on your Windows machine. *(Running without Admin rights or with conflicting local client keys will cause enrollment to fail).*
- You have an active internet connection.
- Your identity provider account (e.g., **adorsys GmbH & Co. KG**) is ready for Single Sign-On (SSO).

> [!NOTE]
> If your machine has already been enrolled into the production environment previously, **do not attempt to re-enroll**. See the note in Step 8 below.

---

## Step-by-Step Installation Guide

### Step 1: Run the Setup Script

1. Press the **Windows Key**, type `PowerShell`, right-click on **Windows PowerShell**, and select **Run as administrator**.
2. Copy and execute the following command:

```powershell
irm https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-agent-installer/refs/tags/v1.1.1/install-scripts/windows.ps1 | iex
```

This command automatically downloads and prepares the latest version of the Wazuh Agent Installer on your machine.

image-20260807-071923.png

---

### Step 2: Launch the Application

1. Open your **Start Menu**.
2. Locate **Wazuh Agent Installer**.
3. Right-click on the app icon and select **Run as administrator**.

image-20260624-064745.png

---

### Step 3: Elevate Privileges (UAC)

When prompted by **Windows User Account Control (UAC)**:

1. Click **Yes** to grant administrator privileges.
2. *Note: Administrator rights are strictly required to install system services, register background agents, and write client security keys.*

image-20260624-064814.png

---

### Step 4: Configure Agent Settings

Once the application opens:

1. From the **Wazuh Manager** dropdown, select:
   - `wazuh.adorsys.team` **(prod)**
2. Toggle **Install NetBird** to **ON** (turned blue).

image-20260806-121756.png

---

### Step 5: Start Installation

1. Click the **Start Installation** button.
2. Watch the built-in terminal window for real-time progress as components are downloaded and installed.

> [!TIP]
> Installation typically takes **5–10 minutes** depending on network speed.

image-20260806-122234.png

---

### Step 6: Verify Installation Status

1. Click the **Overview** tab in the left sidebar.
2. Verify that:
   - All installed components display an **INSTALLED** badge.
   - No errors or warning indicators are present.

image-20260806-122557.png

---

### Step 7: NetBird Enrollment

1. Click the **NetBird** tab in the left sidebar.
2. From the **Management URL** dropdown, select `netbird.guard.adorsys.com`.
3. Click **Connect NetBird**.
   - Your default browser will automatically open and redirect to the NetBird authentication page.
4. Select **adorsys GmbH & Co. KG** (or your organization's Identity Provider) and log in.

image-20260806-155032.png

---

### Step 8: Wazuh Agent Enrollment

> [!IMPORTANT]
> **DO NOT re-enroll if your machine is already enrolled!**
> If your device is already registered with the Wazuh Manager, attempting to run enrollment again will fail with an error. **This is expected behavior** to prevent overwriting existing encryption keys. If your machine is already enrolled and connected, you can skip this step.

1. Click the **Enrollment** tab in the left sidebar.
2. Configure the endpoints:
   - **OAuth2 Issuer URL**: `login.wazuh.adorsys.team / adorsys`
   - **Certificate Endpoint**: `cert.wazuh.adorsys.team` **(Production)**
3. Click **Start Enrollment**.
4. Authenticate in your browser using your **adorsys GmbH & Co. KG** SSO credentials when prompted.

image-20260807-065703.png  
image-20260807-070149.png  
image-20260807-070212.png  
image-20260807-070245.png  

---

### Step 9: Restart Your Machine

> [!IMPORTANT]
> **A machine restart is required to finalize setup!**

Once installation and enrollment are complete, **restart your Windows computer**. 

Restarting ensures that:
- The latest version of the **Wazuh Agent Status Monitor** service is loaded into your system tray.
- Environment paths and background security services initialize properly.

image-20260807-restart-status.png

---

## Troubleshooting & Common Errors

### 1. Enrollment Fails / Error During Enrollment
- **Cause 1 (Already Enrolled)**: If the agent was previously registered, re-running enrollment without clearing old keys will fail. Check the **Overview** tab to see if your agent is already installed and running.
- **Cause 2 (Missing Administrator Privileges)**: Ensure you launched PowerShell and the Wazuh Agent Installer app using **Run as administrator**.

### 2. Need Further Help?
If you encounter unexpected issues during setup:
- Collect your installation logs using the **Save Logs** button inside the app.
- Reach out to the support team on Slack: **`#Wazuh-Support`** and attach your logs.
