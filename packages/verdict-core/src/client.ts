import {
  PhishingScanResponse,
  PasswordCheckResponse,
  EmailCheckResponse,
  DeepfakeScanResponse,
  ClaimCheckResponse,
  IncidentFusionResponse,
  LedgerVerifyResponse,
  BotMessageRequest,
  BotMessageResponse,
  ModuleVerdict
} from './types.js';

export interface ClientConfig {
  baseUrl?: string;
  fetchFn?: typeof fetch;
  timeoutMs?: number;
}

export class TrustShieldApiClient {
  private readonly baseUrl: string;
  private readonly fetchFn: typeof fetch;
  private readonly timeoutMs: number;

  constructor(config?: ClientConfig) {
    this.baseUrl = (config?.baseUrl || 'http://localhost:8080').replace(/\/+$/, '');
    this.fetchFn = config?.fetchFn || (typeof fetch !== 'undefined' ? fetch.bind(globalThis) : (null as unknown as typeof fetch));
    this.timeoutMs = config?.timeoutMs || 15000;
  }

  private async request<T>(path: string, options?: RequestInit): Promise<T> {
    if (!this.fetchFn) {
      throw new Error('fetch is not available in the current environment');
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const url = `${this.baseUrl}${path.startsWith('/') ? path : `/${path}`}`;
      const res = await this.fetchFn(url, {
        ...options,
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          ...(options?.headers || {})
        }
      });

      if (!res.ok) {
        let errBody: unknown;
        try {
          errBody = await res.json();
        } catch {
          errBody = await res.text();
        }
        throw new Error(`TrustShield API error (${res.status}): ${JSON.stringify(errBody)}`);
      }

      return (await res.json()) as T;
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Scans a URL for phishing characteristics, lexical features, and external reputation.
   */
  public async scanUrl(url: string, context: string = 'WEB_CONSOLE'): Promise<PhishingScanResponse> {
    return this.request<PhishingScanResponse>('/api/v1/phishing/scan', {
      method: 'POST',
      body: JSON.stringify({ url, context })
    });
  }

  /**
   * Checks a password exposure via k-anonymous HIBP range lookup.
   */
  public async checkPassword(password: string): Promise<PasswordCheckResponse> {
    return this.request<PasswordCheckResponse>('/api/v1/breach/password', {
      method: 'POST',
      body: JSON.stringify({ password })
    });
  }

  /**
   * Checks an email against known breach directories.
   */
  public async checkEmail(email: string): Promise<EmailCheckResponse> {
    return this.request<EmailCheckResponse>('/api/v1/breach/email', {
      method: 'POST',
      body: JSON.stringify({ email })
    });
  }

  /**
   * Scans media (image or video) for synthetic manipulation and forensic anomalies.
   */
  public async scanMedia(params: {
    base64: string;
    filename?: string;
    mediaType?: string;
    context?: string;
  }): Promise<DeepfakeScanResponse> {
    return this.request<DeepfakeScanResponse>('/api/v1/deepfake/scan', {
      method: 'POST',
      body: JSON.stringify({
        imageBase64: params.base64,
        filename: params.filename || 'media.jpg',
        mediaType: params.mediaType || 'IMAGE',
        context: params.context || 'WEB_CONSOLE'
      })
    });
  }

  /**
   * Verifies a news claim or forwarded text against fact-check directories.
   */
  public async checkClaim(params: {
    claimText: string;
    mediaBase64?: string;
    mediaType?: string;
    context?: string;
  }): Promise<ClaimCheckResponse> {
    return this.request<ClaimCheckResponse>('/api/v1/fakenews/check', {
      method: 'POST',
      body: JSON.stringify({
        claimText: params.claimText,
        mediaBase64: params.mediaBase64,
        mediaType: params.mediaType || 'TEXT',
        context: params.context || 'WEB_CONSOLE'
      })
    });
  }

  /**
   * Evaluates cross-modal threat fusion rules (R1-R5) over modular verdicts.
   */
  public async evaluateFusion(
    verdicts: ModuleVerdict[],
    ledgerVerified: boolean = true
  ): Promise<IncidentFusionResponse> {
    return this.request<IncidentFusionResponse>('/api/v1/fusion/evaluate', {
      method: 'POST',
      body: JSON.stringify({
        verdicts,
        ledgerVerified
      })
    });
  }

  /**
   * Verifies the cryptographic hash chain of the append-only ledger.
   */
  public async verifyLedger(): Promise<LedgerVerifyResponse> {
    return this.request<LedgerVerifyResponse>('/api/v1/integrity/verify', {
      method: 'GET'
    });
  }

  /**
   * Submits a message to the conversational bot service.
   */
  public async sendBotMessage(msg: BotMessageRequest): Promise<BotMessageResponse> {
    return this.request<BotMessageResponse>('/api/v1/bot/message', {
      method: 'POST',
      body: JSON.stringify(msg)
    });
  }

  /**
   * Health check to ensure gateway is reachable.
   */
  public async getGatewayHealth(): Promise<{ status: string }> {
    return this.request<{ status: string }>('/actuator/health', {
      method: 'GET'
    });
  }
}
