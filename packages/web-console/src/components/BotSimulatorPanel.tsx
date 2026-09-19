import React, { useState } from 'react';
import { TrustShieldApiClient, BotMessageResponse } from '@trustshield/verdict-core';
import { MessageSquare, Send, ShieldCheck } from 'lucide-react';

interface Props {
  client: TrustShieldApiClient;
}

interface ChatMessage {
  id: string;
  sender: 'user' | 'bot';
  text: string;
  timestamp: string;
  response?: BotMessageResponse;
}

export const BotSimulatorPanel: React.FC<Props> = ({ client }) => {
  const [channel, setChannel] = useState<'WHATSAPP' | 'TELEGRAM' | 'WEB_CHAT'>('WHATSAPP');
  const [input, setInput] = useState('/rules');
  const [loading, setLoading] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: '1',
      sender: 'bot',
      text: '🛡️ *Welcome to TrustShield Cyber-Defense Bot*\n\nForward any suspicious message, link, image, or video directly to this chat.\nType `/help` or `/rules` for guidance.',
      timestamp: '21:40'
    }
  ]);

  const handleSend = async (messageText?: string) => {
    const textToSend = messageText || input;
    if (!textToSend.trim()) return;

    const userMsg: ChatMessage = {
      id: String(Date.now()),
      sender: 'user',
      text: textToSend,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setLoading(true);

    try {
      const res = await client.sendBotMessage({
        channel,
        senderId: channel === 'WHATSAPP' ? '+919876543210' : '@security_analyst',
        messageText: textToSend
      });

      const botMsg: ChatMessage = {
        id: String(Date.now() + 1),
        sender: 'bot',
        text: res.replyText,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        response: res
      };
      setMessages((prev) => [...prev, botMsg]);
    } catch (err: unknown) {
      const errorMsg: ChatMessage = {
        id: String(Date.now() + 1),
        sender: 'bot',
        text: `⚠️ Error contacting bot gateway: ${err instanceof Error ? err.message : String(err)}`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setLoading(false);
    }
  };

  const presets = [
    { label: '/rules (Fusion Rules)', text: '/rules' },
    { label: '/help (Guide)', text: '/help' },
    { label: 'Phishing Forward', text: 'Please verify your bank details urgently at http://sbi-verification.tk/auth' },
    { label: 'UNESCO Viral Hoax', text: 'UNESCO declared Indian national anthem the best in the world!' },
    { label: 'Password Exposure', text: 'password: MySecretPassword123!' }
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div style={{ backgroundColor: 'var(--bg-card)', padding: '1.5rem', borderRadius: '0.75rem', border: '1px solid var(--border-color)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', marginBottom: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <MessageSquare style={{ color: '#22C55E' }} size={24} />
            <div>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>Conversational Bot Gateway Simulator (Port 8089)</h2>
              <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
                Test WhatsApp and Telegram conversational threat queries with real mobile markdown formatting.
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Channel:</span>
            <select
              value={channel}
              onChange={(e) => setChannel(e.target.value as any)}
              style={{
                padding: '0.35rem 0.75rem',
                backgroundColor: '#0F172A',
                border: '1px solid #334155',
                borderRadius: '0.375rem',
                color: 'white',
                fontSize: '0.85rem'
              }}
            >
              <option value="WHATSAPP">WhatsApp (Meta Cloud API)</option>
              <option value="TELEGRAM">Telegram Bot</option>
              <option value="WEB_CHAT">Web Chat</option>
            </select>
          </div>
        </div>

        {/* Quick Prompts */}
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', alignSelf: 'center' }}>Quick Messages:</span>
          {presets.map((p) => (
            <button
              key={p.label}
              onClick={() => {
                setInput(p.text);
                handleSend(p.text);
              }}
              style={{
                fontSize: '0.75rem',
                padding: '0.25rem 0.5rem',
                backgroundColor: '#1E293B',
                color: '#CBD5E1',
                border: '1px solid #334155',
                borderRadius: '0.375rem',
                cursor: 'pointer'
              }}
            >
              {p.label}
            </button>
          ))}
        </div>

        {/* Phone Chat Frame */}
        <div
          style={{
            maxWidth: '600px',
            margin: '0 auto',
            backgroundColor: '#0F172A',
            border: '2px solid #334155',
            borderRadius: '1rem',
            overflow: 'hidden',
            boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.5)'
          }}
        >
          {/* Chat Header */}
          <div style={{ backgroundColor: '#1E293B', padding: '0.75rem 1rem', display: 'flex', alignItems: 'center', gap: '0.75rem', borderBottom: '1px solid #334155' }}>
            <div style={{ width: '36px', height: '36px', borderRadius: '50%', backgroundColor: '#10B981', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <ShieldCheck size={20} color="white" />
            </div>
            <div>
              <div style={{ fontWeight: 700, fontSize: '0.9rem' }}>TrustShield Security Bot</div>
              <div style={{ fontSize: '0.7rem', color: '#10B981' }}>● Online · Port 8089 ({channel})</div>
            </div>
          </div>

          {/* Chat Messages Body */}
          <div style={{ padding: '1rem', minHeight: '360px', maxHeight: '480px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {messages.map((m) => (
              <div
                key={m.id}
                style={{
                  alignSelf: m.sender === 'user' ? 'flex-end' : 'flex-start',
                  maxWidth: '85%',
                  padding: '0.75rem 1rem',
                  borderRadius: m.sender === 'user' ? '0.75rem 0.75rem 0.15rem 0.75rem' : '0.75rem 0.75rem 0.75rem 0.15rem',
                  backgroundColor: m.sender === 'user' ? '#0369A1' : '#1E293B',
                  color: 'white',
                  fontSize: '0.85rem',
                  whiteSpace: 'pre-wrap',
                  border: m.sender === 'bot' ? '1px solid #334155' : 'none'
                }}
              >
                {m.text}
                <div style={{ fontSize: '0.65rem', color: 'rgba(255, 255, 255, 0.5)', textAlign: 'right', marginTop: '0.25rem' }}>
                  {m.timestamp}
                </div>
              </div>
            ))}
            {loading && (
              <div style={{ alignSelf: 'flex-start', padding: '0.5rem 1rem', backgroundColor: '#1E293B', borderRadius: '0.5rem', fontSize: '0.8rem', color: '#94A3B8' }}>
                TrustShield is analyzing threat indicators...
              </div>
            )}
          </div>

          {/* Input Box */}
          <div style={{ padding: '0.75rem', backgroundColor: '#1E293B', borderTop: '1px solid #334155', display: 'flex', gap: '0.5rem' }}>
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') handleSend(); }}
              placeholder="Send message, link, claim, or /help..."
              style={{
                flex: 1,
                padding: '0.6rem 1rem',
                backgroundColor: '#0F172A',
                border: '1px solid #334155',
                borderRadius: '0.5rem',
                color: 'white',
                fontSize: '0.85rem'
              }}
            />
            <button
              onClick={() => handleSend()}
              disabled={loading}
              style={{
                padding: '0.6rem 1rem',
                backgroundColor: '#10B981',
                color: 'white',
                border: 'none',
                borderRadius: '0.5rem',
                cursor: loading ? 'not-allowed' : 'pointer'
              }}
            >
              <Send size={18} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
