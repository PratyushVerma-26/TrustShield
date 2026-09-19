package com.trustshield.phishing.ml;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Extracts 26 lexical features from a URL for phishing classification.
 *
 * <p>Operates purely over the URL string without network round-trips for sub-millisecond
 * latency. Incorporates public suffix resolution to isolate registered domain names from multi-level TLDs.
 *
 * <p>Feature order is contractual and must strictly match {@code featureNames} defined in the trained model JSON.
 */
public final class UrlFeatureExtractor {

    /** Feature order. Changing this invalidates every trained model file. */
    public static final String[] FEATURE_NAMES = {
            "url_length",                  // 0
            "host_length",                 // 1
            "path_length",                 // 2
            "query_length",                // 3
            "num_dots_in_host",            // 4
            "num_hyphens_in_host",         // 5
            "num_subdomains",              // 6
            "num_digits_in_host",          // 7
            "digit_ratio_in_host",         // 8
            "host_entropy",                // 9
            "is_ip_literal",               // 10
            "is_punycode",                 // 11
            "has_at_symbol",               // 12
            "has_double_slash_in_path",    // 13
            "is_https",                    // 14
            "has_explicit_port",           // 15
            "num_path_segments",           // 16
            "num_query_params",            // 17
            "num_encoded_chars",           // 18
            "num_sensitive_keywords",      // 19
            "brand_impersonation",         // 20
            "suspicious_tld",              // 21
            "is_shortener",                // 22
            "longest_host_token_len",      // 23
            "num_hyphens_in_url",          // 24
            "has_suspicious_extension"     // 25
    };

    /** Human-readable explanation per feature, surfaced to end users as signals. */
    public static final String[] FEATURE_DESCRIPTIONS = {
            "Unusually long web address",
            "Unusually long domain name",
            "Long path after the domain",
            "Long query string",
            "Many dots in the domain, suggesting stacked subdomains",
            "Hyphens in the domain, common in look-alike domains",
            "Deeply nested subdomains",
            "Digits inside the domain name",
            "High proportion of digits in the domain",
            "Domain uses an unusually wide mix of different characters",
            "Address uses a raw IP instead of a domain name",
            "Domain uses punycode, which can disguise look-alike characters",
            "Address contains an @ symbol, which can hide the real destination",
            "Doubled slash inside the path, often used to confuse parsers",
            "Connection is encrypted with HTTPS",
            "Address specifies a non-standard port",
            "Many folders in the path",
            "Many query parameters",
            "Percent-encoded characters that may hide the true address",
            "Contains words used to create urgency about accounts or payments",
            "Impersonates a known bank or brand without being its real domain",
            "Uses a top-level domain heavily abused for abuse and fraud",
            "Uses a link shortener, which conceals the real destination",
            "Contains one very long unbroken chunk in the domain",
            "Many hyphens across the whole address",
            "Links directly to an executable or installer file"
    };

    public static final int FEATURE_COUNT = FEATURE_NAMES.length;

    /**
     * Words that appear disproportionately in credential-harvesting URLs.
     * Includes India-specific banking vocabulary (UPI, netbanking, KYC, PAN,
     * Aadhaar) because the deployment target is Indian users and generic
     * English-only keyword lists miss a large share of local phishing.
     */
    private static final Set<String> SENSITIVE_KEYWORDS = Set.of(
            "login", "signin", "sign-in", "logon", "verify", "verification",
            "secure", "security", "account", "update", "confirm", "validate",
            "password", "passwd", "credential", "otp", "mpin", "pin",
            "bank", "banking", "netbanking", "upi", "payment", "pay", "wallet",
            "kyc", "aadhaar", "aadhar", "pan", "refund", "reward", "prize",
            "unlock", "suspended", "blocked", "expire", "expired", "recover",
            "invoice", "billing", "transaction", "webscr", "authorize"
    );

    /**
     * Brands whose names are commonly used in look-alike domains, mapped to the
     * registrable domains that legitimately own them. A brand token appearing in
     * a hostname that does not resolve to one of these domains is strong evidence
     * of impersonation.
     *
     * <p>Skewed towards Indian financial services because that is where the
     * observed local phishing volume concentrates.
     */
    private static final Map<String, Set<String>> BRAND_DOMAINS = buildBrandDomains();

    private static Map<String, Set<String>> buildBrandDomains() {
        Map<String, Set<String>> m = new HashMap<>();
        m.put("sbi", Set.of("sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com"));
        m.put("onlinesbi", Set.of("onlinesbi.sbi", "onlinesbi.com"));
        m.put("hdfc", Set.of("hdfcbank.com", "hdfc.com"));
        m.put("icici", Set.of("icicibank.com", "icici.com"));
        m.put("axis", Set.of("axisbank.com"));
        m.put("kotak", Set.of("kotak.com"));
        m.put("paytm", Set.of("paytm.com", "paytmbank.com"));
        m.put("phonepe", Set.of("phonepe.com"));
        m.put("googlepay", Set.of("pay.google.com", "google.com"));
        m.put("bhim", Set.of("npci.org.in", "bhimupi.org.in"));
        m.put("npci", Set.of("npci.org.in"));
        m.put("irctc", Set.of("irctc.co.in", "irctc.com"));
        m.put("incometax", Set.of("incometax.gov.in", "incometaxindia.gov.in"));
        m.put("uidai", Set.of("uidai.gov.in"));
        m.put("epfindia", Set.of("epfindia.gov.in"));
        m.put("amazon", Set.of("amazon.com", "amazon.in"));
        m.put("flipkart", Set.of("flipkart.com"));
        m.put("paypal", Set.of("paypal.com"));
        m.put("microsoft", Set.of("microsoft.com", "live.com", "office.com"));
        m.put("apple", Set.of("apple.com", "icloud.com"));
        m.put("google", Set.of("google.com", "google.co.in"));
        m.put("facebook", Set.of("facebook.com", "fb.com"));
        m.put("instagram", Set.of("instagram.com"));
        m.put("whatsapp", Set.of("whatsapp.com", "wa.me"));
        m.put("netflix", Set.of("netflix.com"));
        return Map.copyOf(m);
    }

    /** TLDs with persistently high abuse rates relative to legitimate registrations. */
    private static final Set<String> SUSPICIOUS_TLDS = Set.of(
            "tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz", "click", "link",
            "work", "support", "loan", "review", "country", "stream", "download",
            "racing", "win", "bid", "date", "faith", "zip", "mov", "rest", "cam"
    );

    private static final Set<String> SHORTENER_HOSTS = Set.of(
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
            "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "tiny.cc", "bitly.com",
            "s.id", "shorte.st", "adf.ly", "t.ly", "linktr.ee"
    );

    private static final Set<String> SUSPICIOUS_EXTENSIONS = Set.of(
            ".exe", ".apk", ".scr", ".bat", ".cmd", ".msi", ".dmg", ".jar",
            ".vbs", ".ps1", ".hta", ".iso", ".img"
    );

    private static final Pattern IPV4 =
            Pattern.compile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");

    /**
     * Public suffixes with open registration: anyone may buy a name under them,
     * so membership carries no information about the registrant.
     *
     * <p>{@code co.in} belongs here and emphatically not in
     * {@link #VERIFIED_SUFFIXES}. It is sold to the general public, so
     * {@code hdfcbank-netbanking.co.in} is a perfectly purchasable phishing
     * domain and must keep scoring as one.
     */
    private static final Set<String> OPEN_SUFFIXES = Set.of(
            "co.in", "co.uk", "com.au", "co.jp", "net.in", "org.in",
            "com.br", "co.za", "com.sg", "org.uk", "firm.in", "gen.in",
            "ind.in", "co.nz", "com.my", "com.ph", "co.th", "com.tr", "com.mx"
    );

    /**
     * Public suffixes whose registry verifies the registrant's identity and
     * eligibility before delegating a name.
     *
     * <p>The consequence matters for feature 20. Under an open suffix, a brand
     * token in the hostname is evidence of impersonation, because anyone can
     * register it. Under an accredited suffix it is not, because the registry
     * has already established that the registrant is who the name says. India's
     * {@code bank.in} is the case that prompted this: the Reserve Bank of India
     * restricts it to licensed Indian banks, with IDRBT as exclusive registrar,
     * so a name existing there is positive evidence rather than negative.
     *
     * <p>Two limits, stated rather than assumed. First, suppression applies to
     * this one signal; every other feature still scores normally, so a name
     * under an accredited suffix is not thereby declared safe. Second, the check
     * reads the host's <em>actual trailing</em> suffix, so
     * {@code hdfc.bank.in.secure-login.tk} gets no benefit at all: its suffix is
     * {@code tk}. {@code UrlFeatureExtractorTest} pins that case, because a
     * registry allowlist that could be spoofed by prefixing would be worse than
     * no allowlist.
     */
    private static final Set<String> VERIFIED_SUFFIXES = Set.of(
            "bank.in", "fin.in",
            "gov.in", "nic.in", "mil.in", "ac.in", "edu.in", "res.in",
            "gov.uk", "ac.uk", "edu.au", "gov.au"
    );

    /** Single-label TLDs with the same accreditation property. */
    private static final Set<String> VERIFIED_TLDS = Set.of(
            "bank", "insurance", "gov", "mil", "edu"
    );

    /** Multi-part public suffixes that need two labels to reach the registrable domain. */
    private static final Set<String> TWO_LABEL_SUFFIXES = union(OPEN_SUFFIXES, VERIFIED_SUFFIXES);

    private static Set<String> union(Set<String> a, Set<String> b) {
        Set<String> out = new HashSet<>(a);
        out.addAll(b);
        return Set.copyOf(out);
    }

    /**
     * Words attackers glue onto a brand token inside a single label.
     *
     * <p>This exists to make feature 20 a token match rather than a substring
     * match. {@code host.contains("axis")} is true of {@code praxis.com} and
     * {@code host.contains("apple")} is true of {@code pineapple.co}, both of
     * which were being reported as bank impersonation. Requiring the brand to
     * fill a whole dot/hyphen token, or to sit next to a recognised word inside
     * one, keeps {@code hdfcbank-secure.top} and {@code verifysbi.xyz} caught
     * while dropping the accidental substrings.
     */
    private static final Set<String> GLUE_WORDS = buildGlueWords();

    private static Set<String> buildGlueWords() {
        Set<String> out = new HashSet<>(SENSITIVE_KEYWORDS);
        out.addAll(Set.of(
                "online", "net", "web", "portal", "india", "in", "app", "my",
                "new", "home", "live", "care", "help", "support", "id", "user",
                "customer", "official", "service", "services", "mobile", "www",
                "co", "corp"));
        return Set.copyOf(out);
    }

    private UrlFeatureExtractor() {
    }

    /**
     * Computes the raw (unstandardised) feature vector for a URL.
     *
     * <p>Never throws on malformed input: a URL that cannot be parsed is itself
     * weak evidence of abuse, so parse failure degrades to string-level features
     * rather than rejecting the request.
     *
     * @param rawUrl the URL as submitted by the user
     * @return array of length {@link #FEATURE_COUNT}, in {@link #FEATURE_NAMES} order
     */
    public static double[] extract(String rawUrl) {
        String url = rawUrl == null ? "" : rawUrl.trim();
        String lower = url.toLowerCase(Locale.ROOT);

        // Ensure a scheme so URI parsing yields a host rather than treating
        // everything as a path.
        String forParsing = lower.startsWith("http://") || lower.startsWith("https://")
                ? url
                : "http://" + url;

        String host = "";
        String path = "";
        String query = "";
        int explicitPort = -1;
        boolean parsedHttps = lower.startsWith("https://");

        try {
            URI uri = new URI(forParsing);
            host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
            path = uri.getRawPath() == null ? "" : uri.getRawPath();
            query = uri.getRawQuery() == null ? "" : uri.getRawQuery();
            explicitPort = uri.getPort();
        } catch (URISyntaxException e) {
            // Fall back to crude splitting; a URL this malformed is already odd.
            String stripped = forParsing.replaceFirst("^https?://", "");
            int slash = stripped.indexOf('/');
            host = slash < 0 ? stripped : stripped.substring(0, slash);
            path = slash < 0 ? "" : stripped.substring(slash);
            int q = path.indexOf('?');
            if (q >= 0) {
                query = path.substring(q + 1);
                path = path.substring(0, q);
            }
            int colon = host.indexOf(':');
            if (colon >= 0) {
                host = host.substring(0, colon);
            }
        }

        double[] f = new double[FEATURE_COUNT];

        f[0] = url.length();
        f[1] = host.length();
        f[2] = path.length();
        f[3] = query.length();
        f[4] = countChar(host, '.');
        f[5] = countChar(host, '-');
        f[6] = Math.max(0, countChar(host, '.') - publicSuffixLabelCount(host));
        f[7] = host.chars().filter(Character::isDigit).count();
        f[8] = host.isEmpty() ? 0.0 : f[7] / host.length();
        f[9] = shannonEntropy(host);
        f[10] = IPV4.matcher(host).matches() ? 1.0 : 0.0;
        f[11] = host.contains("xn--") ? 1.0 : 0.0;
        f[12] = url.contains("@") ? 1.0 : 0.0;
        f[13] = path.contains("//") ? 1.0 : 0.0;
        f[14] = parsedHttps ? 1.0 : 0.0;
        f[15] = (explicitPort != -1 && explicitPort != 80 && explicitPort != 443) ? 1.0 : 0.0;
        f[16] = countPathSegments(path);
        f[17] = query.isEmpty() ? 0.0 : query.split("&").length;
        f[18] = countOccurrences(lower, "%");
        f[19] = countSensitiveKeywords(lower, host);
        f[20] = detectBrandImpersonation(host) ? 1.0 : 0.0;
        f[21] = SUSPICIOUS_TLDS.contains(extractTld(host)) ? 1.0 : 0.0;
        f[22] = SHORTENER_HOSTS.contains(host) ? 1.0 : 0.0;
        f[23] = longestTokenLength(host);
        f[24] = countChar(url, '-');
        f[25] = hasSuspiciousExtension(path) ? 1.0 : 0.0;

        return f;
    }

    /**
     * Detects brand impersonation tokens in hostnames, such as subdomains or hyphenated labels.
     *
     * <p>Requires whole-token matching and validates against verified brand domains in {@link #BRAND_DOMAINS}
     * to prevent false positives on legitimate institutional subdomains.
     */
    static boolean detectBrandImpersonation(String host) {
        if (host.isEmpty()) {
            return false;
        }
        String registrable = registrableDomain(host);
        for (Map.Entry<String, Set<String>> entry : BRAND_DOMAINS.entrySet()) {
            String brand = entry.getKey();
            if (!brandTokenPresent(host, brand)) {
                continue;
            }
            boolean legitimate = entry.getValue().stream()
                    .anyMatch(d -> registrable.equals(d) || host.equals(d) || host.endsWith("." + d));
            if (legitimate) {
                continue;
            }
            if (isVerifiedRegistry(host)) {
                continue;
            }
            return true;
        }
        return false;
    }

    /**
     * True when {@code brand} fills a whole dot- or hyphen-delimited token of the
     * host, or sits adjacent to a recognised word inside one.
     *
     * <p>The former substring test made every host containing the letters of a
     * brand a suspect: {@code praxis.com} matched {@code axis} and
     * {@code pineapple.co} matched {@code apple}. Requiring the remainder of the
     * token to be a word in {@link #GLUE_WORDS} keeps the attack patterns
     * ({@code hdfcbank}, {@code verifysbi}, {@code sbionline}) and drops the
     * accidents ({@code pr} and {@code pine} are not words here).
     */
    static boolean brandTokenPresent(String host, String brand) {
        for (String token : host.split("[.\\-_]")) {
            if (token.isEmpty()) {
                continue;
            }
            if (token.equals(brand)) {
                return true;
            }
            if (token.startsWith(brand) && GLUE_WORDS.contains(token.substring(brand.length()))) {
                return true;
            }
            if (token.endsWith(brand)
                    && GLUE_WORDS.contains(token.substring(0, token.length() - brand.length()))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Number of trailing labels that belong to the public suffix rather than to
     * the registrant. Two for {@code co.in} or {@code bank.in}, otherwise one.
     */
    static int publicSuffixLabelCount(String host) {
        String[] labels = host.split("\\.");
        if (labels.length >= 3
                && TWO_LABEL_SUFFIXES.contains(labels[labels.length - 2] + "." + labels[labels.length - 1])) {
            return 2;
        }
        return 1;
    }

    /**
     * True when the host sits under a registry that verifies its registrants.
     *
     * <p>Reads only the actual trailing suffix. {@code hdfc.bank.in.evil.tk} is
     * not exempt, because its suffix is {@code tk}.
     */
    static boolean isVerifiedRegistry(String host) {
        String[] labels = host.split("\\.");
        if (labels.length >= 3
                && VERIFIED_SUFFIXES.contains(labels[labels.length - 2] + "." + labels[labels.length - 1])) {
            return true;
        }
        return labels.length >= 2 && VERIFIED_TLDS.contains(labels[labels.length - 1]);
    }

    /**
     * Best-effort registrable domain ("example.co.in" from "a.b.example.co.in").
     *
     * <p>Uses a small hard-coded suffix list rather than the full Public Suffix
     * List. This is a known simplification: it will mis-handle uncommon
     * multi-label suffixes. Documented as a limitation rather than hidden.
     */
    static String registrableDomain(String host) {
        String[] labels = host.split("\\.");
        if (labels.length <= 2) {
            return host;
        }
        String lastTwo = labels[labels.length - 2] + "." + labels[labels.length - 1];
        if (TWO_LABEL_SUFFIXES.contains(lastTwo) && labels.length >= 3) {
            return labels[labels.length - 3] + "." + lastTwo;
        }
        return lastTwo;
    }

    private static String extractTld(String host) {
        int lastDot = host.lastIndexOf('.');
        return lastDot < 0 || lastDot == host.length() - 1
                ? ""
                : host.substring(lastDot + 1);
    }

    /**
     * Counts urgency and credential vocabulary, ignoring the host's public
     * suffix.
     *
     * <p>The suffix is substituted out rather than the haystack rebuilt, so
     * keywords in the path, query and fragment still count. Without this,
     * {@code bank} in {@code hdfc.bank.in} scored as an urgency keyword, which
     * meant India's official banking suffix incriminated every bank that used
     * it.
     */
    private static int countSensitiveKeywords(String lowerUrl, String host) {
        String haystack = lowerUrl;
        if (!host.isEmpty()) {
            int idx = haystack.indexOf(host);
            if (idx >= 0) {
                String[] labels = host.split("\\.");
                int suffixLabels = publicSuffixLabelCount(host);
                String registrant = String.join(".",
                        Arrays.copyOfRange(labels, 0, Math.max(0, labels.length - suffixLabels)));
                haystack = haystack.substring(0, idx) + registrant + haystack.substring(idx + host.length());
            }
        }
        int count = 0;
        for (String keyword : SENSITIVE_KEYWORDS) {
            if (haystack.contains(keyword)) {
                count++;
            }
        }
        return count;
    }

    private static boolean hasSuspiciousExtension(String path) {
        String lowerPath = path.toLowerCase(Locale.ROOT);
        for (String ext : SUSPICIOUS_EXTENSIONS) {
            if (lowerPath.endsWith(ext)) {
                return true;
            }
        }
        return false;
    }

    private static int countPathSegments(String path) {
        if (path.isEmpty() || path.equals("/")) {
            return 0;
        }
        int count = 0;
        for (String segment : path.split("/")) {
            if (!segment.isEmpty()) {
                count++;
            }
        }
        return count;
    }

    private static int longestTokenLength(String host) {
        int longest = 0;
        for (String token : host.split("[.\\-_]")) {
            longest = Math.max(longest, token.length());
        }
        return longest;
    }

    private static int countChar(String s, char c) {
        int count = 0;
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == c) {
                count++;
            }
        }
        return count;
    }

    private static int countOccurrences(String s, String sub) {
        int count = 0;
        int idx = s.indexOf(sub);
        while (idx >= 0) {
            count++;
            idx = s.indexOf(sub, idx + sub.length());
        }
        return count;
    }

    /**
     * Shannon entropy over the characters of a string, in bits.
     *
     * <p><strong>What this measures, and what it does not.</strong> This is a
     * unigram entropy: it depends only on the multiset of characters, so it is
     * completely invariant to their order. It therefore measures <em>character
     * diversity</em>, not randomness in any linguistic sense.
     *
     * <p>The consequence is worth stating plainly, because the obvious intuition
     * about this feature is wrong. {@code "x7k2mq9v"} and {@code "hdfcbank"} both
     * consist of eight distinct characters over eight positions, so both score
     * exactly {@code log2(8) == 3.0} bits. This feature cannot tell an
     * algorithmically generated host from a pronounceable brand name of the same
     * length and character variety. {@code UrlFeatureExtractorTest} pins that
     * equality with an explicit assertion so the limitation cannot be quietly
     * forgotten.
     *
     * <p>What it does capture is real but narrower: hosts padded with repeated
     * characters or drawn from a small alphabet score low, and long hosts mixing
     * letters, digits and hyphens score high. Distinguishing pronounceable
     * strings from random ones requires character <em>bigram</em> or trigram
     * statistics fitted to real domain names, which is a separate feature and is
     * on the roadmap rather than implemented here.
     */
    static double shannonEntropy(String s) {
        if (s.isEmpty()) {
            return 0.0;
        }
        int[] counts = new int[128];
        int considered = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 128) {
                counts[c]++;
                considered++;
            }
        }
        if (considered == 0) {
            return 0.0;
        }
        double entropy = 0.0;
        for (int count : counts) {
            if (count > 0) {
                double p = (double) count / considered;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }
        return entropy;
    }
}
