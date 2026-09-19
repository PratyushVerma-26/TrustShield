package com.trustshield.bot.intent;

import com.trustshield.bot.dto.BotMessageRequest;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Classifies user intent from conversational chat messages and attachments.
 */
@Component
public class MessageIntentClassifier {

    public enum IntentType {
        COMMAND,
        PHISHING_URL,
        MULTIMODAL_MEDIA,
        VIRAL_CLAIM,
        PASSWORD_BREACH,
        GENERAL_SAFETY
    }

    public record IntentResult(
            IntentType intentType,
            String commandName,
            List<String> extractedUrls,
            String cleanedQueryText
    ) {}

    private static final Pattern URL_PATTERN = Pattern.compile(
            "\\b(https?://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|])|\\b([a-zA-Z0-9-]+\\.(?:com|org|net|xyz|top|ru|cn|info|online|site|app|cc)(?:/[^\\s]*)?)\\b",
            Pattern.CASE_INSENSITIVE
    );

    /**
     * Classifies intent and extracts relevant entities from a message request.
     */
    public IntentResult classify(BotMessageRequest request) {
        String text = request.messageText() != null ? request.messageText().trim() : "";
        String mediaType = request.mediaType() != null ? request.mediaType().toUpperCase(Locale.ROOT) : "NONE";

        // 1. Slash commands: /start, /help, /check, /rules, /stats, etc.
        if (text.startsWith("/")) {
            int spaceIdx = text.indexOf(' ');
            String cmd = (spaceIdx != -1 ? text.substring(0, spaceIdx) : text).toLowerCase(Locale.ROOT);
            String arg = (spaceIdx != -1 ? text.substring(spaceIdx + 1).trim() : "");
            return new IntentResult(IntentType.COMMAND, cmd, extractUrls(arg), arg);
        }

        // 2. Multimodal media: Attached image, video, or audio
        if (!mediaType.equals("NONE") && request.mediaBase64() != null && !request.mediaBase64().isBlank()) {
            return new IntentResult(IntentType.MULTIMODAL_MEDIA, null, extractUrls(text), text);
        }

        // 3. Password or breach query
        String lower = text.toLowerCase(Locale.ROOT);
        if (lower.startsWith("password:") || lower.startsWith("check password") || lower.startsWith("pwned:")) {
            String pwd = text.substring(text.indexOf(':') != -1 ? text.indexOf(':') + 1 : 14).trim();
            return new IntentResult(IntentType.PASSWORD_BREACH, null, List.of(), pwd);
        }

        // 4. Web URLs: phishing scan candidate
        List<String> urls = extractUrls(text);
        if (!urls.isEmpty()) {
            return new IntentResult(IntentType.PHISHING_URL, null, urls, text);
        }

        // 5. News claims or viral forwards
        if (text.length() >= 25 || lower.contains("forwarded") || lower.contains("breaking") ||
            lower.contains("unesco") || lower.contains("scheme") || lower.contains("declared") ||
            lower.contains("minister") || lower.contains("govt")) {
            return new IntentResult(IntentType.VIRAL_CLAIM, null, List.of(), text);
        }

        // 6. Default: general conversational safety guidance
        return new IntentResult(IntentType.GENERAL_SAFETY, null, List.of(), text);
    }

    public List<String> extractUrls(String text) {
        if (text == null || text.isBlank()) {
            return List.of();
        }
        List<String> urls = new ArrayList<>();
        Matcher matcher = URL_PATTERN.matcher(text);
        while (matcher.find()) {
            String url = matcher.group(0);
            if (!url.startsWith("http://") && !url.startsWith("https://")) {
                url = "https://" + url;
            }
            urls.add(url);
        }
        return urls;
    }
}
