package com.trustshield.bot.format;

import com.trustshield.bot.dto.BotMessageResponse;
import com.trustshield.common.dto.IncidentId;
import com.trustshield.common.dto.ModuleVerdict;
import com.trustshield.common.dto.ThreatLevel;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Formats modular and fused threat verdicts into mobile-friendly WhatsApp/Telegram markdown messages.
 */
@Component
public class BotResponseFormatter {

    /**
     * Formats a ModuleVerdict into a conversational BotMessageResponse.
     */
    public BotMessageResponse formatVerdict(
            IncidentId incidentId,
            String channel,
            String recipientId,
            String category,
            ModuleVerdict verdict,
            long latencyMs) {

        ThreatLevel level = verdict.threatLevel();
        int score = verdict.riskScore();
        List<String> recommendations = buildRecommendations(level, category);

        StringBuilder sb = new StringBuilder();
        sb.append(getBadge(level)).append(" *(").append(score).append("/100)*\n\n");
        sb.append("📋 *Category:* ").append(category).append("\n");
        sb.append("🔍 *Verdict:* ").append(verdict.verdict()).append("\n");

        if (verdict.explanation() != null && !verdict.explanation().isBlank()) {
            sb.append("📝 *Analysis:* ").append(verdict.explanation()).append("\n\n");
        } else {
            sb.append("\n");
        }

        sb.append("💡 *Recommended Actions:*\n");
        for (String rec : recommendations) {
            sb.append("• ").append(rec).append("\n");
        }

        sb.append("\n🛡️ _TrustShield AI Cyber-Defense_ · `Ref: ").append(incidentId.value()).append("`");

        return new BotMessageResponse(
                incidentId,
                channel,
                recipientId,
                sb.toString(),
                level,
                score,
                category,
                recommendations,
                latencyMs
        );
    }

    /**
     * Formats built-in command replies (e.g. /help, /start).
     */
    public BotMessageResponse formatCommandResponse(
            IncidentId incidentId,
            String channel,
            String recipientId,
            String commandName) {

        StringBuilder sb = new StringBuilder();
        if ("/start".equalsIgnoreCase(commandName) || "/help".equalsIgnoreCase(commandName)) {
            sb.append("🛡️ *Welcome to TrustShield Cyber-Defense Bot*\n\n");
            sb.append("Forward any suspicious message, link, image, or video directly to this chat:\n\n");
            sb.append("🔗 *Links & Websites:* Paste a link to scan for zero-day phishing\n");
            sb.append("📰 *News & Messages:* Forward news to verify against fact-checking directories\n");
            sb.append("📸 *Photos & Videos:* Send media to analyze for deepfakes, AI voices, or spliced chyrons\n");
            sb.append("🔑 *Password Security:* Type `password: <your_password>` to check breach exposure\n\n");
            sb.append("📌 *Commands:*\n");
            sb.append("• `/help` - Show instructions\n");
            sb.append("• `/rules` - View cross-modal fusion rules\n");
            sb.append("• `/info` - View system architecture & integrity\n\n");
            sb.append("🔒 _All scans are cryptographically recorded in an append-only audit ledger._");
        } else if ("/rules".equalsIgnoreCase(commandName)) {
            sb.append("⚖️ *TrustShield Auditable Fusion Rules (R1–R5)*\n\n");
            sb.append("• *R1 (Dangerous Escalation):* Any confirmed threat makes the incident DANGEROUS\n");
            sb.append("• *R2 (Multimodal Escalation):* 2+ SUSPICIOUS signals escalate to DANGEROUS\n");
            sb.append("• *R3 (Coverage Invariant):* Unverified media can NEVER be declared SAFE\n");
            sb.append("• *R4 (Ledger Tamper Override):* Broken audit chain flags critical tampering\n");
            sb.append("• *R5 (Coordinated Multiplier):* Phishing combined with deepfakes compounds risk\n");
        } else {
            sb.append("ℹ️ *TrustShield Status:* All forensic & fact-checking microservices are operational.\n");
            sb.append("Send any link, message, or media file to begin real-time analysis.");
        }

        return new BotMessageResponse(
                incidentId,
                channel,
                recipientId,
                sb.toString(),
                ThreatLevel.SAFE,
                0,
                "SYSTEM_COMMAND",
                List.of("Send content for threat scanning"),
                5L
        );
    }

    private String getBadge(ThreatLevel level) {
        return switch (level) {
            case DANGEROUS -> "🚨 *DANGEROUS THREAT DETECTED*";
            case SUSPICIOUS -> "⚠️ *SUSPICIOUS CONTENT DETECTED*";
            case SAFE -> "🛡️ *NO THREATS DETECTED*";
            case LOW -> "ℹ️ *LOW RISK / MINIMAL THREAT*";
            case UNKNOWN -> "❓ *INCONCLUSIVE / UNVERIFIED*";
        };
    }

    private List<String> buildRecommendations(ThreatLevel level, String category) {
        List<String> recs = new ArrayList<>();
        switch (level) {
            case DANGEROUS -> {
                if ("PHISHING_URL".equals(category)) {
                    recs.add("Do NOT click this link or enter passwords / OTPs.");
                    recs.add("If already opened, change your credentials immediately.");
                    recs.add("Warn the sender that their link or account is compromised.");
                } else if ("VIRAL_HOAX".equals(category)) {
                    recs.add("This claim has been debunked by verified fact-checkers.");
                    recs.add("Do NOT forward or reshare this claim in group chats.");
                } else if ("SYNTHETIC_MEDIA".equals(category)) {
                    recs.add("Media shows signs of AI manipulation or synthetic voice cloning.");
                    recs.add("Do NOT make financial transfers based on this media.");
                } else {
                    recs.add("Block the sender and do not interact with this content.");
                }
            }
            case SUSPICIOUS -> {
                recs.add("Exercise caution; avoid entering personal information.");
                recs.add("Verify via an independent official channel before trusting.");
            }
            case UNKNOWN -> {
                recs.add("Fine forensic traces were destroyed by compression or claim is unindexed.");
                recs.add("TrustShield refuses to falsely certify unverified content as safe.");
                recs.add("Verify with official source documents directly.");
            }
            case SAFE, LOW -> {
                recs.add("Content passed all automated threat heuristic scans.");
                recs.add("Always stay alert to unexpected login or payment requests.");
            }
        }
        return recs;
    }
}
