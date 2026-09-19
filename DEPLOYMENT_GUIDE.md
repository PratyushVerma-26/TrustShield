# TrustShield Public Deployment Guide

This guide provides comprehensive, step-by-step instructions to make all three **standalone** TrustShield applications publicly accessible across the internet:
1. **The Web Console** (Cyber-Defense Operations HUD for security teams & analysts)
2. **The Conversational Bot** (Standalone Web Chat, Telegram Bot, & WhatsApp Cloud API for public users)
3. **The Mobile App** (Standalone Android APK & iOS build for on-device threat protection)

---

## Architecture Overview: 3 Standalone Channels

```
                           +------------------------------------------------------+
                           |                 PUBLIC INTERNET                      |
                           +------------------------------------------------------+
                                      |                     |                 |
                                      v                     v                 v
                         +-----------------------+ +------------------+ +-----------------------+
                         | Standalone Web HUD    | | Standalone Bot   | | Standalone Mobile App |
                         | (Operations Console)  | | (/chat, Telegram,| | (Android APK / iOS)   |
                         |                       | |  WhatsApp Cloud) | |                       |
                         +-----------------------+ +------------------+ +-----------------------+
                                      |                     |                 |
                                      +------------------+  |  +--------------+
                                                         v  v  v
                                              +------------------------+
                                              |  TrustShield Gateway   |
                                              |      (Port 8080)       |
                                              +------------------------+
                                                          |
                                      +-------------------+-------------------+
                                      |                   |                   |
                                      v                   v                   v
                               +--------------+    +--------------+    +--------------+
                               | Microservice |    | Microservice |    | Microservice |
                               |   Clusters   |    | (Deepfake &  |    |  (Phishing,  |
                               | (Core AI)    |    |  Fake News)  |    |   Breach)    |
                               +--------------+    +--------------+    +--------------+
```

Each component is 100% decoupled:
- **Web Console** contains no simulated phone or chat box. It is a dedicated cyber-defense analyst cockpit.
- **Bot Portal** is accessible either via its own responsive web portal (`/chat`), Telegram, or WhatsApp.
- **Mobile App** installs natively on Android/iOS with zero dependency on the web browser.

---

## Part 1: Making the Web Console & API Gateway Public

The TrustShield Gateway (port 8080) serves both the Web Console (`/`) and the Public Chat Portal (`/chat`), while proxying all threat detection microservices (`/api/v1/*`).

### Option A: Instant Free Public Access via Cloudflare Tunnel (Recommended)
Cloudflare Tunnel provides an enterprise-grade, encrypted HTTPS URL with DDoS protection, without requiring open firewall ports or a static public IP.

1. **Install Cloudflare Tunnel (`cloudflared`)**:
   - **Windows (PowerShell)**:
     ```powershell
     winget install --id Cloudflare.cloudflared
     ```
   - **Linux (Debian/Ubuntu)**:
     ```bash
     curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
     sudo dpkg -i cloudflared.deb
     ```
   - **macOS**:
     ```bash
     brew install cloudflared
     ```

2. **Start TrustShield Gateway**:
   ```bash
   # Ensure the Gateway is running on port 8080
   mvn spring-boot:run -pl trustshield-gateway
   ```

3. **Expose with a Single Command**:
   ```bash
   cloudflared tunnel --url http://localhost:8080
   ```

4. **Access Your Public URLs**:
   Cloudflare outputs a public HTTPS link (e.g., `https://random-words.trycloudflare.com`):
   - **Web Console**: `https://random-words.trycloudflare.com/`
   - **Standalone Web Chat**: `https://random-words.trycloudflare.com/chat`
   - **API Gateway**: `https://random-words.trycloudflare.com/api/v1/...`

*(For permanent custom domains like `defense.yourdomain.com`, run `cloudflared tunnel login` and configure a named tunnel in your Cloudflare dashboard).*

---

### Option B: Quick Testing via Ngrok
1. Install [Ngrok](https://ngrok.com/):
   ```bash
   ngrok http 8080
   ```
2. Ngrok provides a public forwarding URL: `https://<your-id>.ngrok-free.app`.

---

### Option C: Production VPS / Cloud Deployment (AWS, DigitalOcean, Hetzner, Railway, Render)

1. **Build the Production Artifacts**:
   ```bash
   # Build the Web Console
   cd packages/web-console
   npm install
   npm run build
   cd ../..

   # Build Gateway & Backend Microservices
   mvn clean package -DskipTests
   ```

2. **Deploy via Docker Compose**:
   ```bash
   docker compose -f infra/docker-compose.yml up -d
   ```

3. **Configure Nginx Reverse Proxy with SSL (Certbot)**:
   ```nginx
   server {
       server_name trustshield.yourdomain.com;

       location / {
           proxy_pass http://127.0.0.1:8080;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```
   Generate free SSL certificate:
   ```bash
   sudo certbot --nginx -d trustshield.yourdomain.com
   ```

---

## Part 2: Making the Conversational Bot Public

TrustShield Bot is accessible to the public through three distinct interfaces:
1. Direct Browser Web Chat
2. Telegram Bot
3. WhatsApp Cloud API

### 1. Standalone Browser Web Chat
- **URL**: `https://<YOUR_PUBLIC_DOMAIN>/chat` (or `https://<YOUR_PUBLIC_DOMAIN>/chat.html`)
- **Audience**: Anyone with a smartphone or PC browser.
- **Features**: Real-time link verification, credential breach lookup, fake news debunking, and multimodal threat triage.

### 2. Public Telegram Bot Setup
1. **Create Bot on Telegram**:
   - Open Telegram and message [@BotFather](https://t.me/BotFather).
   - Send `/newbot`.
   - Choose a display name: `TrustShield Sentinel`.
   - Choose a unique username: `TrustShieldDefenseBot` (must end with `bot`).
   - Copy the generated HTTP API token (e.g., `7123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ`).

2. **Register the Public Webhook**:
   Set your public domain to receive Telegram updates:
   ```bash
   curl -F "url=https://<YOUR_PUBLIC_DOMAIN>/webhook/telegram" https://api.telegram.org/bot<YOUR_TELEGRAM_TOKEN>/setWebhook
   ```
   Telegram will respond:
   ```json
   {"ok":true,"result":true,"description":"Webhook was set"}
   ```

3. **Configure the Service**:
   Add the token to your environment or `trustshield-bot-service/src/main/resources/application.properties`:
   ```properties
   trustshield.bot.telegram-token=${TELEGRAM_BOT_TOKEN:YOUR_TELEGRAM_TOKEN}
   ```
4. **Public Access**:
   Users can now search `@TrustShieldDefenseBot` in Telegram, click **Start**, and send suspicious messages, links, or files for instant analysis.

### 3. WhatsApp Cloud API Setup (Meta for Developers)
1. **Create Meta App**:
   - Navigate to [Meta for Developers](https://developers.facebook.com/).
   - Click **Create App** > Select **Business** type.
   - Add the **WhatsApp** product.

2. **Configure Webhook**:
   - Go to **WhatsApp** > **Configuration** > **Webhook**.
   - **Callback URL**: `https://<YOUR_PUBLIC_DOMAIN>/webhook/whatsapp`
   - **Verify Token**: `trustshield_webhook_token_2026` (configurable in `trustshield-bot-service`)
   - Click **Verify and Save**.
   - Under Webhook fields, click **Manage** and subscribe to `messages`.

3. **Test & Launch**:
   - Under **API Setup**, add a test recipient phone number or connect a verified Business phone number.
   - Anyone sending a message to this WhatsApp number will receive instant AI security verdicts.

---

## Part 3: Making the Mobile App Public & Distributable

The mobile app is a native Expo / React Native application in `packages/mobile-app`. You can distribute it as a direct-download Android APK or publish it to the Google Play Store and Apple App Store.

### 1. Point the App to Your Public Server
Before building, update the API endpoint to your public domain.
In `packages/mobile-app/App.tsx`:
```typescript
// Replace localhost with your public domain
const API_BASE = 'https://<YOUR_PUBLIC_DOMAIN>';
```

### 2. Generate a Standalone Android APK (Direct User Download)
Using Expo Application Services (EAS Build), you can generate a standalone `.apk` that anyone can download and install on their Android phone without developer tools:

1. **Install EAS CLI**:
   ```bash
   npm install -g eas-cli
   ```

2. **Login to Expo** (Free account at [expo.dev](https://expo.dev)):
   ```bash
   npx eas login
   ```

3. **Navigate to Mobile App Directory**:
   ```bash
   cd packages/mobile-app
   ```

4. **Initialize EAS Project**:
   ```bash
   npx eas build:configure
   ```

5. **Build the Standalone APK**:
   ```bash
   npx eas build -p android --profile preview
   ```
   - EAS will build the app on Expo cloud servers.
   - Upon completion, EAS provides a direct download URL for the `.apk` file (e.g., `https://expo.dev/artifacts/eas/.../app-preview.apk`).

6. **Distribute to Users**:
   - Host the `.apk` on your server: `https://<YOUR_PUBLIC_DOMAIN>/downloads/trustshield.apk`.
   - Provide a QR code or download link on your website.
   - Users open the link on Android, download the `.apk`, and tap **Install**.

---

### 3. Quick Testing via Expo Go (No Build Required)
For testing on iOS or Android devices without building:
1. Install **Expo Go** from Google Play or App Store.
2. In `packages/mobile-app`:
   ```bash
   npm start
   ```
3. Scan the QR code displayed in the terminal using your phone camera (iOS) or Expo Go app (Android).

---

### 4. Publishing to Google Play & Apple App Store
When ready for official app store distribution:
- **Android App Bundle (AAB)**:
  ```bash
  npx eas build -p android --profile production
  npx eas submit -p android
  ```
- **iOS App (IPA)**:
  ```bash
  npx eas build -p ios --profile production
  npx eas submit -p ios
  ```

---

## Part 4: Verification & Smoke Testing Checklist

| Application | Verification Step | Expected Result |
|---|---|---|
| **Web Console** | Navigate to `https://<YOUR_DOMAIN>/` | Cyber-Defense HUD loads with 6 active vectors, live alerts, and no embedded bot simulator. |
| **Standalone Web Chat** | Navigate to `https://<YOUR_DOMAIN>/chat` | Responsive chat interface opens; sending `test` returns formatted response. |
| **Telegram Bot** | Send `/start` and `https://evil-bank.xyz` in Telegram | Bot responds with Phishing Risk Score, DNS flags, and Safe Browsing verdict. |
| **WhatsApp Bot** | Send `Check: Urgent password reset required` | Bot replies with Social Engineering breakdown and confidence score. |
| **Mobile App** | Install APK on Android phone and scan a URL | App evaluates threat using both local edge rules and cloud microservices. |

---

## Summary of Public Access Endpoints

| Service | Public Access Link | Target Audience |
|---|---|---|
| **Web Console** | `https://<YOUR_DOMAIN>/` | Security Analysts, Incident Response |
| **Bot Web Chat** | `https://<YOUR_DOMAIN>/chat` | General Public, Internal Employees |
| **Telegram Bot** | `https://t.me/<YOUR_BOT_USERNAME>` | Mobile & Desktop Telegram Users |
| **WhatsApp Bot** | WhatsApp Business Phone Number | WhatsApp Users Worldwide |
| **Mobile App APK** | `https://<YOUR_DOMAIN>/downloads/trustshield.apk` | Android Smartphone Users |
