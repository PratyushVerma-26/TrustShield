/**
 * TrustShield Mobile Application - Endpoint Configuration
 *
 * Defaults to localhost:8080 (for local testing/emulators).
 * For production standalone APK or LAN testing, replace with your public HTTPS
 * API Gateway domain (e.g., https://api.yourtrustshield.com).
 */
export const GATEWAY_BASE_URL =
  process.env.EXPO_PUBLIC_GATEWAY_URL || 'http://localhost:8080';
