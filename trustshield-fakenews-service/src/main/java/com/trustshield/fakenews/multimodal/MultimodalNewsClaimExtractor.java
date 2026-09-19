package com.trustshield.fakenews.multimodal;

import com.trustshield.common.dto.ClaimCheckRequest;
import com.trustshield.common.dto.ClaimCheckResponse.MultimodalExtraction;
import com.trustshield.fakenews.directory.NewsSourceCredibilityDirectory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Multimodal news claim extractor for image and video news items.
 *
 * <p>Extracts textual headlines and claims from:
 * <ul>
 *   <li>Visual lower-third news chyrons and television tickers.</li>
 *   <li>Image IPTC/EXIF metadata headers (Caption, Headline, ObjectName).</li>
 *   <li>Video ISO BMFF container metadata (Title, Description, Comment atoms).</li>
 *   <li>Embedded news broadcast text streams and source channel branding.</li>
 * </ul>
 */
@Component
public class MultimodalNewsClaimExtractor {

    private static final Logger log = LoggerFactory.getLogger(MultimodalNewsClaimExtractor.class);

    private static final Pattern URL_PATTERN = Pattern.compile("https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}(/[^\\s]*)?");
    private static final Pattern DOMAIN_PATTERN = Pattern.compile("\\b([a-zA-Z0-9-]+\\.(?:com|org|net|in|co\\.uk|gov|edu|gov\\.in|news|info))\\b", Pattern.CASE_INSENSITIVE);

    private final NewsChyronAnalyzer chyronAnalyzer;
    private final NewsSourceCredibilityDirectory sourceDirectory;

    public record ExtractedNewsResult(
            MultimodalExtraction extraction,
            NewsChyronAnalyzer.ChyronAnalysis chyronAnalysis,
            String effectiveClaimText,
            String detectedSourceDomain
    ) {}

    public MultimodalNewsClaimExtractor(
            NewsChyronAnalyzer chyronAnalyzer,
            NewsSourceCredibilityDirectory sourceDirectory) {
        this.chyronAnalyzer = chyronAnalyzer;
        this.sourceDirectory = sourceDirectory;
    }

    /**
     * Extracts news claims and metadata from multimodal news requests.
     */
    public ExtractedNewsResult extractClaim(ClaimCheckRequest request) {
        String claimText = request.claimText() != null ? request.claimText().trim() : "";
        String mediaType = request.mediaType() != null ? request.mediaType().toUpperCase(Locale.ROOT) : "TEXT";
        String context = request.context() != null ? request.context() : "";

        // If purely text request with no media payload:
        if ((request.mediaBase64() == null || request.mediaBase64().isBlank()) &&
            (request.mediaFilename() == null || request.mediaFilename().isBlank())) {
            String detectedDomain = detectSourceDomain(claimText, context, null);
            return new ExtractedNewsResult(
                    new MultimodalExtraction(false, "TEXT", null, false, detectedDomain, 1.0),
                    NewsChyronAnalyzer.ChyronAnalysis.clean(),
                    claimText,
                    detectedDomain
            );
        }

        byte[] mediaBytes = decodeMediaBytes(request.mediaBase64());
        String filename = request.mediaFilename() != null ? request.mediaFilename() : "media_payload";

        boolean isVideo = mediaType.equals("VIDEO") || isVideoFilename(filename);
        String extractedHeadline = null;
        NewsChyronAnalyzer.ChyronAnalysis chyronAnalysis = NewsChyronAnalyzer.ChyronAnalysis.clean();
        double confidence = 0.5;

        if (isVideo) {
            extractedHeadline = extractVideoMetadataHeadline(mediaBytes);
            confidence = extractedHeadline != null ? 0.85 : 0.40;
        } else {
            // Image News
            chyronAnalysis = chyronAnalyzer.analyze(mediaBytes, filename);
            extractedHeadline = extractImageMetadataHeadline(mediaBytes);
            if (extractedHeadline == null && chyronAnalysis.extractedBannerText() != null) {
                extractedHeadline = chyronAnalysis.extractedBannerText();
                confidence = 0.75;
            } else if (extractedHeadline != null) {
                confidence = 0.90;
            }
        }

        // Determine effective claim text: request text takes precedence, fallback to extracted headline
        String effectiveText = claimText;
        if (effectiveText.isBlank() && extractedHeadline != null && !extractedHeadline.isBlank()) {
            effectiveText = extractedHeadline;
        }

        String detectedDomain = detectSourceDomain(effectiveText, context, filename);

        MultimodalExtraction extraction = new MultimodalExtraction(
                true,
                isVideo ? "VIDEO" : "IMAGE",
                extractedHeadline,
                chyronAnalysis.chyronDetected(),
                detectedDomain,
                confidence
        );

        return new ExtractedNewsResult(extraction, chyronAnalysis, effectiveText, detectedDomain);
    }

    private byte[] decodeMediaBytes(String base64) {
        if (base64 == null || base64.isBlank()) {
            return new byte[0];
        }
        try {
            String clean = base64.contains(",") ? base64.substring(base64.indexOf(",") + 1) : base64;
            return Base64.getDecoder().decode(clean.trim());
        } catch (Exception e) {
            log.warn("Failed to base64 decode media payload: {}", e.getMessage());
            return new byte[0];
        }
    }

    private boolean isVideoFilename(String filename) {
        if (filename == null) return false;
        String lower = filename.toLowerCase(Locale.ROOT);
        return lower.endsWith(".mp4") || lower.endsWith(".mov") || lower.endsWith(".avi") || lower.endsWith(".webm");
    }

    /**
     * Extracts headline from IPTC / EXIF / XMP metadata blocks inside image bytes.
     */
    private String extractImageMetadataHeadline(byte[] data) {
        if (data == null || data.length < 16) return null;

        String ascii = new String(data, 0, Math.min(data.length, 65536), StandardCharsets.ISO_8859_1);

        // Check for IPTC 0x1C markers
        for (int i = 0; i < Math.min(data.length - 10, 65536); i++) {
            if (data[i] == 0x1C && data[i + 1] == 0x02) {
                int tag = data[i + 2] & 0xFF;
                // Tag 0x05 = Object Name / Title, Tag 0x78 = Caption / Abstract, Tag 0x69 = Headline
                if (tag == 0x05 || tag == 0x78 || tag == 0x69) {
                    int len = ((data[i + 3] & 0xFF) << 8) | (data[i + 4] & 0xFF);
                    if (len > 0 && len < 1024 && (i + 5 + len) <= data.length) {
                        String value = new String(data, i + 5, len, StandardCharsets.UTF_8).trim();
                        if (!value.isBlank() && value.length() > 5) {
                            return value;
                        }
                    }
                }
            }
        }

        // Check for text chunks in PNG (tEXtTitle, tEXtHeadline) or XMP dc:title
        int dcTitleIdx = ascii.indexOf("<dc:title>");
        if (dcTitleIdx != -1) {
            int endIdx = ascii.indexOf("</dc:title>", dcTitleIdx);
            if (endIdx != -1) {
                return cleanXmlString(ascii.substring(dcTitleIdx + 10, endIdx));
            }
        }

        int dcDescIdx = ascii.indexOf("<dc:description>");
        if (dcDescIdx != -1) {
            int endIdx = ascii.indexOf("</dc:description>", dcDescIdx);
            if (endIdx != -1) {
                return cleanXmlString(ascii.substring(dcDescIdx + 16, endIdx));
            }
        }

        return null;
    }

    /**
     * Extracts headline from ISO BMFF (MP4/MOV) container atoms.
     */
    private String extractVideoMetadataHeadline(byte[] data) {
        if (data == null || data.length < 32) return null;

        String ascii = new String(data, 0, Math.min(data.length, 65536), StandardCharsets.ISO_8859_1);

        // \xa9nam = Title atom
        int titleIdx = ascii.indexOf("\u00a9nam");
        if (titleIdx != -1 && titleIdx + 8 < data.length) {
            String snippet = extractAtomString(data, titleIdx);
            if (snippet != null && !snippet.isBlank()) return snippet;
        }

        // desc / \xa9cmt = Description / Comment atom
        int descIdx = ascii.indexOf("\u00a9cmt");
        if (descIdx == -1) {
            descIdx = ascii.indexOf("desc");
        }
        if (descIdx != -1 && descIdx + 8 < data.length) {
            String snippet = extractAtomString(data, descIdx);
            if (snippet != null && !snippet.isBlank()) return snippet;
        }

        return null;
    }

    private String extractAtomString(byte[] data, int atomTagIdx) {
        try {
            int textStart = atomTagIdx + 4;
            // Skip data atom wrapper if present
            if (textStart + 8 < data.length) {
                String potentialData = new String(data, textStart + 4, 4, StandardCharsets.US_ASCII);
                if ("data".equals(potentialData)) {
                    textStart += 16; // Skip data atom header + flags
                }
            }

            int maxLen = Math.min(256, data.length - textStart);
            if (maxLen <= 0) return null;

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < maxLen; i++) {
                byte b = data[textStart + i];
                if (b == 0 || b < 32) {
                    if (sb.length() > 8) break;
                    continue;
                }
                sb.append((char) b);
            }
            String res = sb.toString().trim();
            return res.length() >= 5 ? res : null;
        } catch (Exception e) {
            return null;
        }
    }

    private String cleanXmlString(String raw) {
        return raw.replaceAll("<[^>]+>", "").replaceAll("\\s+", " ").trim();
    }

    /**
     * Resolves the originating news source domain from text, context, or filename.
     */
    public String detectSourceDomain(String text, String context, String filename) {
        // 1. Search in URL patterns
        String combined = (text != null ? text : "") + " " + (context != null ? context : "") + " " + (filename != null ? filename : "");
        Matcher urlMatcher = URL_PATTERN.matcher(combined);
        if (urlMatcher.find()) {
            return sourceDirectory.extractDomain(urlMatcher.group(0));
        }

        // 2. Search for explicit domain patterns
        Matcher domainMatcher = DOMAIN_PATTERN.matcher(combined);
        if (domainMatcher.find()) {
            return sourceDirectory.extractDomain(domainMatcher.group(1));
        }

        // 3. Match against known source brand names in directory
        NewsSourceCredibilityDirectory.SourceCredibility eval = sourceDirectory.evaluateSource(combined);
        if (eval.isKnownSource()) {
            return eval.domain();
        }

        return null;
    }
}
