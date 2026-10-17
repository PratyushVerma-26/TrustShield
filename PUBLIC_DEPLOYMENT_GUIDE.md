# TrustShield: Production Public Deployment & Standalone Channel Guide

This guide provides step-by-step instructions for deploying and publicly hosting the **TrustShield Cyber-Defense Platform**. In strict adherence to the project architecture, the three user-facing channels are **completely standalone and decoupled**:
1. **Standalone Web Console**: An enterprise React 18 operations cockpit for threat analysts.
2. **Standalone Conversational Bot**: An omnichannel cyber-defense assistant accessible via Telegram, Meta WhatsApp Cloud API, and direct web chat.
3. **Standalone Mobile Application**: A native installable React Native / Expo application distributable as an Android `.apk` or iOS app.

All three channels interact securely with the **Unified API Gateway (Port 8080)**, which orchestrates downstream microservice inference, cryptographic ledger verification, and rate limiting.

---

```
                       PUBLIC CLIENTS & CHANNELS
  ┌───────────────────────┐  ┌───────────────────────┐  ┌───────────────────────┐
  │  Standalone Web App   │  │   Standalone Bot      │  │ Standalone Mobile App │
  │ (Vercel / Netlify)    │  │ (Telegram / WhatsApp) │  │ (Android APK / EAS)   │
  │ console.trustshield.io│  │  @TrustShieldGuardBot │  │  Native Device Install│
  └───────────┬───────────┘  └───────────┬───────────┘  └───────────┬───────────┘
              │                          │                          │
              └──────────────────┐       │       ┌──────────────────┘
                                 ▼       ▼       ▼
                     ┌───────────────────────────────────────┐
                     │   Cloudflare Tunnel / HTTPS Domain   │
                     │       api.trustshield.io:443          │
                     └───────────────────┬───────────────────┘
                                         │ Reverse Proxy (Port 8080)
                                         ▼
                     ┌───────────────────────────────────────┐
                     │        TrustShield API Gateway        │
                     │  (Rate Limiter, CORS, Fallbacks)      │
                     └───────────────────┬───────────────────┘
                                         │ Docker Network
             ┌──────────────┬────────────┼────────────┬──────────────┐
             ▼              ▼            ▼            ▼              ▼
       ┌──────────┐   ┌──────────┐ ┌──────────┐ ┌──────────┐   ┌──────────┐
       │ Phishing │   │  Breach  │ │ Deepfake │ │ FakeNews │   │Integrity │
       │ (:8083)  │   │  (:8084) │ │  (:8085) │ │  (:8086) │   │  (:8087) │
       └──────────┘   └──────────┘ └──────────┘ └──────────┘   └────┬─────┘
             │              │            │            │             │
             └──────────────┼────────────┴────────────┘             │
                            ▼                                       │
                      ┌──────────┐                                  │
                      │  Fusion  │◄─────────────────────────────────┘
                      │  (:8088) │
                      └──────────┘
```

---

## 1. Backend Infrastructure Deployment (Microservice Mesh)

Deploy the backend microservices mesh to any cloud Virtual Private Server (VPS) — such as AWS EC2, DigitalOcean, Hetzner, Google Cloud Compute Engine, or Azure VM (recommended specs: 2 vCPU, 4GB RAM, Ubuntu 22.04 LTS / Debian 12).

### Step 1.1: Server Setup & Prerequisites
Connect to your cloud server via SSH:
```bash
ssh user@your-server-ip
```

Install Docker and Docker Compose:
```bash
# Update package lists and install Docker
sudo apt update && sudo apt install -y docker.io docker-compose-v2 git curl
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
newgrp docker
```

### Step 1.2: Clone Repository & Configure Environment
```bash
git clone https://github.com/PratyushVerma-26/TrustShield.git
cd TrustShield

# Copy environment template
cp .env.example .env
nano .env
```

Populate `.env` with your optional external API keys (Safe Browsing, VirusTotal, Fact Check, WhatsApp/Telegram tokens). All microservices operate out-of-the-box using local heuristic models and offline catalogs even if keys are left blank.

### Step 1.3: Launch Microservice Mesh via Docker Compose
```bash
# Build and start all 8 microservices in the background
docker compose up -d --build
```

Verify that all 8 containers are healthy and running:
```bash
docker compose ps
```

Test the local gateway endpoint:
```bash
curl http://localhost:8080/actuator/health
# Expected: {"status":"UP"}
```

---

## 2. Expose API Gateway to Public HTTPS (Cloudflare Tunnel)

To make your backend publicly accessible over HTTPS without opening firewall ports or managing SSL certificates, use **Cloudflare Tunnel** (`cloudflared`).

### Step 2.1: Install `cloudflared` on Your Server
```bash
# Download and install Debian package
curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
sudo dpkg -i cloudflared.deb
```

### Step 2.2: Authenticate & Create Tunnel
```bash
# Log in to your Cloudflare account
cloudflared tunnel login

# Create a tunnel named 'trustshield-prod'
cloudflared tunnel create trustshield-prod
```
Note the generated Tunnel ID (e.g., `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`).

### Step 2.3: Configure Ingress Rules
Create `/etc/cloudflared/config.yml`:
```yaml
tunnel: <YOUR-TUNNEL-ID>
credentials-file: /root/.cloudflared/<YOUR-TUNNEL-ID>.json

ingress:
  # Route public API traffic to the TrustShield Gateway
  - hostname: api.yourdomain.com
    service: http://localhost:8080
  # Default catch-all rule
  - service: http_status:404
```

Route the DNS record:
```bash
cloudflared tunnel route dns trustshield-prod api.yourdomain.com
```

### Step 2.4: Run Tunnel as a System Service
```bash
sudo cloudflared service install
sudo systemctl enable --now cloudflared
```

Your API Gateway is now live on the public internet at `https://api.yourdomain.com` with automated TLS encryption!

*(Alternative for quick demos: use ngrok: `ngrok http 8080`)*

---

## 3. Standalone Channel 1: Web Console Deployment

The **TrustShield Web Console** (`packages/web-console`) is a React 18 single-page application built with Vite and Tailwind CSS. It communicates directly with the public Gateway API.

### Option A: 1-Click Global Edge Deployment via Vercel (Recommended)
1. Fork or push your repository to GitHub.
2. Sign in to [Vercel](https://vercel.com) and click **"Add New Project"**.
3. Import the `TrustShield` repository.
4. Configure the project settings:
   - **Framework Preset**: `Vite`
   - **Root Directory**: `packages/web-console`
   - **Build Command**: `npm run build`
   - **Output Directory**: `dist`
5. Add the Environment Variable:
   - `VITE_GATEWAY_URL`: `https://api.yourdomain.com`
6. Click **Deploy**.

Vercel will build the frontend and serve it globally on edge CDNs at `https://trustshield-console.vercel.app` (or your attached custom domain like `https://console.yourdomain.com`).

### Option B: Deploy on VPS with Nginx
On your VPS:
```bash
cd packages/web-console
npm install
VITE_GATEWAY_URL="https://api.yourdomain.com" npm run build
```
Copy `dist/` to `/var/www/trustshield-console` and serve with Nginx:
```nginx
server {
    listen 80;
    server_name console.yourdomain.com;

    location / {
        root /var/www/trustshield-console;
        index index.html;
        try_files $uri $uri/ /index.html;
    }
}
```

---

## 4. Standalone Channel 2: Conversational Cyber-Defense Bot

The bot runs as an independent microservice (`trustshield-bot-service`) exposing standard webhook interfaces and a direct web chat interface.

### 4.1: Telegram Bot Deployment

#### Step 1: Create Your Bot with BotFather
1. Open Telegram and search for `@BotFather`.
2. Send `/newbot`.
3. Choose a name (e.g., `TrustShield Cyber Defense`) and a username ending in `bot` (e.g., `TrustShieldGuardBot`).
4. Save the HTTP API Token provided (e.g., `123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ`).

#### Step 2: Configure Environment
Add the token to your server `.env`:
```env
TELEGRAM_BOT_TOKEN=123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ
```
Restart the bot container:
```bash
docker compose up -d bot-service
```

#### Step 3: Register the Webhook
Instruct Telegram to forward incoming user messages to your public Gateway:
```bash
curl -F "url=https://api.yourdomain.com/api/v1/bot/webhook/telegram" \
  https://api.telegram.org/bot123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ/setWebhook
```
Expected response:
```json
{"ok":true,"result":true,"description":"Webhook was set"}
```

#### Step 4: Test Your Standalone Bot
Open Telegram, search for `@TrustShieldGuardBot`, and tap `/start`. Send:
- *"Check this URL: https://paypal.com.account-verification-notice.xyz"*
- *"Was my password Password123! exposed?"*
The bot responds with structured threat verdicts, risk scores, and tactical safety advice!

---

### 4.2: Meta WhatsApp Cloud API Deployment

#### Step 1: Create Meta Developer App
1. Navigate to the [Meta for Developers Portal](https://developers.facebook.com/) and log in.
2. Click **My Apps** > **Create App**. Select **Other** > **Business**.
3. Under **Add products to your app**, locate **WhatsApp** and click **Set up**.
4. In the WhatsApp Getting Started dashboard, note:
   - **Temporary access token** (or configure a System User for permanent token).
   - **Phone number ID**.
   - **Test phone number** provided by Meta.

#### Step 2: Configure Webhook Verification
1. In the left sidebar, click **WhatsApp** > **Configuration**.
2. Under **Webhook**, click **Edit**:
   - **Callback URL**: `https://api.yourdomain.com/webhook/whatsapp`
   - **Verify token**: `trustshield_webhook_token_2026` (or the custom value set in your `.env`)
3. Click **Verify and save**. Meta will issue a GET challenge to verify the webhook, which TrustShield validates with HTTP 200.
4. Under **Webhook fields**, click **Manage** and subscribe to `messages`.

#### Step 3: Test on WhatsApp
Send a WhatsApp message from your verified phone number to the Meta test number. The TrustShield bot will parse your threat query and reply with real-time cybersecurity intelligence!

---

### 4.3: Standalone Direct Web Chat (`/chat.html`)
The bot service bundles a responsive standalone web chat interface:
- **Public URL**: `https://api.yourdomain.com/chat.html`
- This page can be bookmarked by end-users or embedded in an iframe on any third-party portal without requiring the Web Console.

---

## 5. Standalone Channel 3: Mobile App Distribution (Android APK & iOS)

The **TrustShield Mobile Application** (`packages/mobile-app`) is built with React Native and Expo. It can be compiled into a standalone installable Android `.apk` package without requiring the user to run Expo Go or node.

### Step 5.1: Install EAS CLI & Log In
On your development machine:
```bash
npm install -g eas-cli
eas login
```
*(If you do not have an Expo account, create one at [https://expo.dev](https://expo.dev) — free tier includes cloud builds).*

### Step 5.2: Configure Gateway Production Endpoint
Edit `packages/mobile-app/src/config.ts` (or set `EXPO_PUBLIC_GATEWAY_URL` in `packages/mobile-app/.env`):
```typescript
export const GATEWAY_BASE_URL = 'https://api.yourdomain.com';
```

### Step 5.3: Build Standalone Android APK (Cloud Build)
In `packages/mobile-app`, the `eas.json` file is already pre-configured for standalone APK generation:
```json
{
  "build": {
    "preview": {
      "distribution": "internal",
      "android": {
        "buildType": "apk"
      }
    }
  }
}
```

Trigger the cloud build:
```bash
cd packages/mobile-app
eas build -p android --profile preview
```

### Step 5.4: Download & Distribute the `.apk`
1. EAS will stream build logs and complete within 3–6 minutes.
2. Upon completion, EAS provides a permanent public download URL and QR code:
   `https://expo.dev/artifacts/eas/.../TrustShield-preview.apk`
3. Download the `.apk` and upload it to your GitHub Releases page:
   `https://github.com/PratyushVerma-26/TrustShield/releases`
4. Any Android user can download and install `TrustShield-preview.apk` directly onto their phone!

### Step 5.5: Instant Local Testing via Expo Go
For immediate testing on iOS or Android devices without building an APK:
```bash
cd packages/mobile-app
npx expo start --tunnel
```
Scan the displayed QR code with the **Expo Go** app on your phone.

---

## 6. Pre-Launch Production Readiness Checklist

Before final demonstration or public launch, execute the automated rehearsal suite to verify the entire platform:

```powershell
# Run the automated rehearsal harness against the public Gateway
powershell -ExecutionPolicy Bypass -File scripts/rehearsal.ps1 -GatewayUrl https://api.yourdomain.com
```

### Verification Matrix

| Channel / Component | Public Access URL | Expected Behavior |
| :--- | :--- | :--- |
| **API Gateway** | `https://api.yourdomain.com/actuator/health` | Returns `{"status":"UP"}` |
| **Ledger Audit** | `https://api.yourdomain.com/api/v1/ledger/verify` | Returns `{"valid":true,"signatureValid":true}` |
| **Web Console** | `https://console.yourdomain.com` | Live analytics cockpit with threat scanners |
| **Web Chat** | `https://api.yourdomain.com/chat.html` | Real-time interactive conversational chat |
| **Telegram Bot** | `https://t.me/TrustShieldGuardBot` | Instant threat assessment replies |
| **WhatsApp Bot** | Meta Test Number | WhatsApp interactive threat assistance |
| **Mobile App** | `TrustShield-preview.apk` | Standalone native on-device threat inspector |

All three channels operate fully standalone with zero inter-channel coupling.
