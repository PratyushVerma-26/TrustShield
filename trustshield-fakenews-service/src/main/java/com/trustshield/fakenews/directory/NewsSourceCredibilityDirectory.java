package com.trustshield.fakenews.directory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Curated directory of news outlets, broadcast channels, and publishing domains
 * providing source credibility evaluation, categorization, and misinformation risk adjustments.
 *
 * <h2>Categorization Schema</h2>
 * <ul>
 *   <li><strong>TRUSTED_MAINSTREAM:</strong> Established wire services and reputable journalistic outlets
 *       with transparent editorial standards and corrections policies (e.g. Reuters, AP, BBC, The Hindu, PIB).</li>
 *   <li><strong>SATIRE_PARODY:</strong> Recognized humorous or satirical publications (e.g. The Onion, Babylon Bee,
 *       The Fauxy). High risk when quotes or headlines are reshared out of context as literal breaking news.</li>
 *   <li><strong>KNOWN_MISINFO_PROPAGANDA:</strong> Documented disinformation distributors, fake news generators,
 *       or state-sponsored covert propaganda networks (e.g. World News Daily Report, InfoWars, Natural News).</li>
 *   <li><strong>QUESTIONABLE_CLICKBAIT:</strong> Sensationalist clickbait farms with unverified or unsourced headlines.</li>
 *   <li><strong>UNKNOWN:</strong> Unindexed or personal domains where credibility cannot be established.</li>
 * </ul>
 */
@Component
public class NewsSourceCredibilityDirectory {

    private static final Logger log = LoggerFactory.getLogger(NewsSourceCredibilityDirectory.class);

    public enum SourceCategory {
        TRUSTED_MAINSTREAM,
        SATIRE_PARODY,
        KNOWN_MISINFO_PROPAGANDA,
        QUESTIONABLE_CLICKBAIT,
        UNKNOWN
    }

    public record SourceCredibility(
            String domain,
            String name,
            SourceCategory category,
            int credibilityScore, // 0 to 100 (higher = more credible)
            int riskScore,        // 0 to 100 (higher = higher threat)
            String rationale,
            boolean isKnownSource
    ) {
        public static SourceCredibility unknown(String raw) {
            return new SourceCredibility(
                    raw,
                    "Unknown or Unindexed Publisher",
                    SourceCategory.UNKNOWN,
                    50,
                    0,
                    "Source domain is not indexed in credibility directory. Credibility cannot be established.",
                    false
            );
        }
    }

    private final Map<String, SourceCredibility> directory = new LinkedHashMap<>();

    public NewsSourceCredibilityDirectory() {
        initDirectory();
    }

    private void initDirectory() {
        // --- 1. Trusted Mainstream Outlets (High Credibility, Low Threat) ---
        addSource("reuters.com", "Reuters News Agency", SourceCategory.TRUSTED_MAINSTREAM, 98, 5,
                "Global international news agency with strict editorial verifiability standards.");
        addSource("apnews.com", "Associated Press", SourceCategory.TRUSTED_MAINSTREAM, 98, 5,
                "Non-profit international news cooperative with verified primary-source reporting.");
        addSource("bbc.com", "BBC News", SourceCategory.TRUSTED_MAINSTREAM, 94, 8,
                "Public service broadcaster with editorial guidelines and dedicated Reality Check verification.");
        addSource("bbc.co.uk", "BBC UK", SourceCategory.TRUSTED_MAINSTREAM, 94, 8,
                "UK public service broadcaster news edition.");
        addSource("afp.com", "Agence France-Presse", SourceCategory.TRUSTED_MAINSTREAM, 96, 6,
                "Global news agency and signatory of the International Fact-Checking Network (IFCN).");
        addSource("pib.gov.in", "Press Information Bureau (Govt of India)", SourceCategory.TRUSTED_MAINSTREAM, 92, 10,
                "Official nodal communications agency with active Fact Check unit.");
        addSource("thehindu.com", "The Hindu", SourceCategory.TRUSTED_MAINSTREAM, 92, 10,
                "Established national newspaper of record with rigorous editorial guidelines.");
        addSource("npr.org", "National Public Radio", SourceCategory.TRUSTED_MAINSTREAM, 92, 10,
                "Public broadcasting organization with verified sourcing standards.");
        addSource("pbs.org", "PBS NewsHour", SourceCategory.TRUSTED_MAINSTREAM, 94, 8,
                "US public television news organization.");
        addSource("aljazeera.com", "Al Jazeera English", SourceCategory.TRUSTED_MAINSTREAM, 88, 15,
                "International news broadcaster covering global events.");
        addSource("theguardian.com", "The Guardian", SourceCategory.TRUSTED_MAINSTREAM, 90, 12,
                "Independent journalistic trust publication.");
        addSource("nytimes.com", "The New York Times", SourceCategory.TRUSTED_MAINSTREAM, 92, 10,
                "Newspaper of record with verified investigative standards.");
        addSource("washingtonpost.com", "The Washington Post", SourceCategory.TRUSTED_MAINSTREAM, 90, 12,
                "Daily newspaper with dedicated fact-checking and investigative team.");
        addSource("snopes.com", "Snopes Fact Check", SourceCategory.TRUSTED_MAINSTREAM, 96, 5,
                "Pioneering digital fact-checking organization.");
        addSource("altnews.in", "Alt News", SourceCategory.TRUSTED_MAINSTREAM, 94, 6,
                "Independent IFCN-certified Indian fact-checking organisation.");
        addSource("boomlive.in", "BOOM Live", SourceCategory.TRUSTED_MAINSTREAM, 94, 6,
                "Independent IFCN-certified fact-checking agency.");
        addSource("politifact.com", "PolitiFact", SourceCategory.TRUSTED_MAINSTREAM, 94, 6,
                "Pulitzer Prize-winning fact-checking organization.");
        addSource("factcheck.org", "FactCheck.org", SourceCategory.TRUSTED_MAINSTREAM, 96, 5,
                "Non-partisan project of the Annenberg Public Policy Center.");

        // --- 2. Satire & Parody Outlets (Satirical, High Risk If Taken As Fact) ---
        addSource("theonion.com", "The Onion", SourceCategory.SATIRE_PARODY, 20, 85,
                "Prominent satirical digital media publication. Content is fabricated parody and humor.");
        addSource("babylonbee.com", "The Babylon Bee", SourceCategory.SATIRE_PARODY, 25, 80,
                "Satirical news website publishing parody commentary. Not factual reporting.");
        addSource("clickhole.com", "ClickHole", SourceCategory.SATIRE_PARODY, 20, 85,
                "Parody website satirizing internet clickbait culture and viral media.");
        addSource("thedailymash.co.uk", "The Daily Mash", SourceCategory.SATIRE_PARODY, 20, 85,
                "British satirical publication featuring parodic news stories.");
        addSource("thefauxy.com", "The Fauxy", SourceCategory.SATIRE_PARODY, 20, 85,
                "Indian entertainment and satirical portal. Stories are fictional humor.");
        addSource("borowitzreport.com", "The Borowitz Report", SourceCategory.SATIRE_PARODY, 25, 80,
                "Satirical column and fiction newsletter.");
        addSource("waterfordwhispersnews.com", "Waterford Whispers News", SourceCategory.SATIRE_PARODY, 20, 85,
                "Irish satirical news and comedy website.");

        // --- 3. Known Misinformation, Propaganda & Hoax Outlets (Extreme Threat) ---
        addSource("worldnewsdailyreport.com", "World News Daily Report", SourceCategory.KNOWN_MISINFO_PROPAGANDA, 5, 96,
                "Known fake news site responsible for numerous viral fabrications and fictional hoaxes.");
        addSource("infowars.com", "InfoWars", SourceCategory.KNOWN_MISINFO_PROPAGANDA, 8, 95,
                "Prominent conspiracy theory and documented disinformation platform.");
        addSource("naturalnews.com", "Natural News", SourceCategory.KNOWN_MISINFO_PROPAGANDA, 10, 92,
                "Medical conspiracy and anti-vaccine misinformation distributor.");
        addSource("beforeitsnews.com", "Before It's News", SourceCategory.KNOWN_MISINFO_PROPAGANDA, 10, 92,
                "Unmoderated conspiracy and unverified rumor clearinghouse.");
        addSource("newspunch.com", "NewsPunch (formerly YourNewsWire)", SourceCategory.KNOWN_MISINFO_PROPAGANDA, 5, 96,
                "Prolific distributor of viral debunked hoaxes and manufactured news.");
        addSource("empirenews.net", "Empire News", SourceCategory.KNOWN_MISINFO_PROPAGANDA, 8, 94,
                "Fabricated viral news website masquerading as authentic journalism.");
        addSource("nationalreport.net", "National Report", SourceCategory.KNOWN_MISINFO_PROPAGANDA, 8, 94,
                "Fake news domain known for generating political and social hoaxes.");
        addSource("prntly.com", "Prntly", SourceCategory.KNOWN_MISINFO_PROPAGANDA, 10, 92,
                "Hyperpartisan fake news blog known for fabricated poll numbers and stories.");
        addSource("rt.com", "RT (Russia Today)", SourceCategory.KNOWN_MISINFO_PROPAGANDA, 25, 85,
                "State-controlled media outlet documented for foreign state disinformation campaigns.");
        addSource("sputniknews.com", "Sputnik News", SourceCategory.KNOWN_MISINFO_PROPAGANDA, 25, 85,
                "State-controlled media outlet documented for weaponized information operations.");

        log.info("Initialized NewsSourceCredibilityDirectory with {} evaluated news domains", directory.size());
    }

    private void addSource(String domain, String name, SourceCategory category, int credibilityScore, int riskScore, String rationale) {
        directory.put(domain.toLowerCase(Locale.ROOT), new SourceCredibility(
                domain.toLowerCase(Locale.ROOT),
                name,
                category,
                credibilityScore,
                riskScore,
                rationale,
                true
        ));
    }

    /**
     * Evaluates a domain, URL, or outlet name against the credibility directory.
     */
    public SourceCredibility evaluateSource(String input) {
        if (input == null || input.isBlank()) {
            return SourceCredibility.unknown("UNKNOWN");
        }

        String normalized = extractDomain(input).toLowerCase(Locale.ROOT);

        // 1. Direct domain match
        if (directory.containsKey(normalized)) {
            return directory.get(normalized);
        }

        // 2. Subdomain match (e.g. factcheck.reuters.com -> reuters.com)
        for (Map.Entry<String, SourceCredibility> entry : directory.entrySet()) {
            String domain = entry.getKey();
            if (normalized.endsWith("." + domain) || normalized.equals(domain)) {
                return entry.getValue();
            }
        }

        // 3. Name or brand token match (e.g. "The Onion", "Reuters", "InfoWars")
        String lowerInput = input.toLowerCase(Locale.ROOT);
        for (SourceCredibility sc : directory.values()) {
            if (lowerInput.contains(sc.name().toLowerCase(Locale.ROOT)) ||
                lowerInput.contains(sc.domain().replace(".com", "").replace(".org", ""))) {
                return sc;
            }
        }

        return SourceCredibility.unknown(normalized);
    }

    /**
     * Normalizes a raw URL or domain string into a clean hostname.
     */
    public String extractDomain(String raw) {
        if (raw == null || raw.isBlank()) {
            return "";
        }
        String trimmed = raw.trim();
        try {
            if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
                URI uri = URI.create(trimmed);
                String host = uri.getHost();
                if (host != null) {
                    trimmed = host;
                }
            }
        } catch (Exception ignored) {
            // fallback to regex extraction
        }

        // Strip leading www.
        if (trimmed.startsWith("www.")) {
            trimmed = trimmed.substring(4);
        }

        // Strip path / query
        int slashIdx = trimmed.indexOf('/');
        if (slashIdx != -1) {
            trimmed = trimmed.substring(0, slashIdx);
        }

        int colonIdx = trimmed.indexOf(':');
        if (colonIdx != -1) {
            trimmed = trimmed.substring(0, colonIdx);
        }

        return trimmed.toLowerCase(Locale.ROOT);
    }

    public Map<String, SourceCredibility> getAllEntries() {
        return Collections.unmodifiableMap(directory);
    }

    public int getSourceCount() {
        return directory.size();
    }
}
