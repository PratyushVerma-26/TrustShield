package com.trustshield.phishing.ml;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Behavioural tests for the lexical feature extractor.
 *
 * <p>These assert on named indices rather than on the whole vector, so a future
 * feature insertion breaks the specific assertion it invalidates instead of
 * producing an opaque array-comparison failure.
 */
class UrlFeatureExtractorTest {

    /** Resolves a feature index by name so the tests survive reordering. */
    private static int idx(String name) {
        for (int i = 0; i < UrlFeatureExtractor.FEATURE_NAMES.length; i++) {
            if (UrlFeatureExtractor.FEATURE_NAMES[i].equals(name)) {
                return i;
            }
        }
        throw new IllegalArgumentException("No such feature: " + name);
    }

    private static double f(String url, String feature) {
        return UrlFeatureExtractor.extract(url)[idx(feature)];
    }

    @Test
    @DisplayName("names and descriptions stay in lockstep")
    void metadataArraysAgree() {
        // If these ever diverge, the service will show the wrong explanation next
        // to the right score, which is worse than showing nothing.
        assertEquals(UrlFeatureExtractor.FEATURE_NAMES.length,
                UrlFeatureExtractor.FEATURE_DESCRIPTIONS.length,
                "Every feature must have a human-readable description");
        assertEquals(UrlFeatureExtractor.FEATURE_NAMES.length,
                UrlFeatureExtractor.FEATURE_COUNT);
        assertEquals(26, UrlFeatureExtractor.FEATURE_COUNT,
                "Changing the feature count invalidates every trained model file");
    }

    @Test
    @DisplayName("malformed input degrades instead of throwing")
    void malformedInputDoesNotThrow() {
        // A URL too broken to parse is itself weak evidence of abuse, so the
        // extractor must produce a vector rather than reject the request.
        for (String bad : new String[]{"", "   ", "not even a url", "http://", "://x", "%%%%"}) {
            double[] v = UrlFeatureExtractor.extract(bad);
            assertNotNull(v, "extract returned null for input: " + bad);
            assertEquals(UrlFeatureExtractor.FEATURE_COUNT, v.length);
            for (double d : v) {
                assertTrue(Double.isFinite(d),
                        "Non-finite feature value for input: " + bad);
            }
        }
        assertEquals(UrlFeatureExtractor.FEATURE_COUNT,
                UrlFeatureExtractor.extract(null).length,
                "null must be handled, not thrown on");
    }

    @Test
    @DisplayName("raw IP hosts are detected")
    void detectsIpLiteral() {
        assertEquals(1.0, f("http://192.168.1.1/login", "is_ip_literal"));
        assertEquals(0.0, f("https://www.hdfcbank.com/", "is_ip_literal"));
    }

    @Test
    @DisplayName("HTTPS is recognised only from the actual scheme")
    void detectsHttps() {
        assertEquals(1.0, f("https://example.com", "is_https"));
        assertEquals(0.0, f("http://example.com", "is_https"));
        // A bare host has no scheme, so it must not be credited with HTTPS.
        assertEquals(0.0, f("example.com", "is_https"));
        // "https" appearing in the path is not a secure connection.
        assertEquals(0.0, f("http://evil.tk/https/secure", "is_https"));
    }

    @Test
    @DisplayName("@ in the URL is flagged")
    void detectsAtSymbol() {
        // http://user@evil.example.org resolves to evil.example.org, not to
        // whatever precedes the @. This is a classic obfuscation.
        assertEquals(1.0, f("http://trusted.com@evil.example.org/", "has_at_symbol"));
        assertEquals(0.0, f("http://evil.example.org/", "has_at_symbol"));
    }

    @Test
    @DisplayName("brand impersonation fires on look-alikes but not on the real domain")
    void detectsBrandImpersonation() {
        // Look-alikes: brand token present, registrable domain not owned by it.
        assertEquals(1.0, f("https://sbi-secure-login.xyz/verify", "brand_impersonation"));
        assertEquals(1.0, f("http://paytm.account-verify.tk/", "brand_impersonation"));
        assertEquals(1.0, f("http://onlinesbi.login-verify.com/", "brand_impersonation"));

        // Genuine domains must not fire, or the false-positive rate makes the
        // product unusable for exactly the sites people visit most.
        assertEquals(0.0, f("https://www.hdfcbank.com/personal/netbanking", "brand_impersonation"));
        assertEquals(0.0, f("https://retail.onlinesbi.sbi/", "brand_impersonation"));
        assertEquals(0.0, f("https://www.icicibank.com/", "brand_impersonation"));
        assertEquals(0.0, f("https://www.amazon.in/orders", "brand_impersonation"));
    }

    @Test
    @DisplayName("abused TLDs and shorteners are recognised")
    void detectsSuspiciousTldAndShortener() {
        assertEquals(1.0, f("http://random-thing.tk/", "suspicious_tld"));
        assertEquals(1.0, f("http://random-thing.xyz/", "suspicious_tld"));
        assertEquals(0.0, f("http://random-thing.com/", "suspicious_tld"));

        assertEquals(1.0, f("https://bit.ly/3xYzAbc", "is_shortener"));
        assertEquals(0.0, f("https://bitly-not-real.com/3xYzAbc", "is_shortener"));
    }

    @Test
    @DisplayName("India-specific banking keywords are counted")
    void countsSensitiveKeywords() {
        // Generic English-only keyword lists miss a large share of local phishing,
        // which is why upi/netbanking/kyc are in the vocabulary.
        assertTrue(f("http://x.tk/netbanking/kyc-update/upi-verify", "num_sensitive_keywords") >= 4);
        assertEquals(0.0, f("https://example.com/blog/post/1", "num_sensitive_keywords"));
    }

    @Test
    @DisplayName("executable download links are flagged")
    void detectsSuspiciousExtension() {
        assertEquals(1.0, f("http://free-stuff.tk/setup.exe", "has_suspicious_extension"));
        assertEquals(1.0, f("http://bank-update.xyz/app.apk", "has_suspicious_extension"));
        assertEquals(0.0, f("http://example.com/report.pdf", "has_suspicious_extension"));
    }

    @Test
    @DisplayName("punycode hosts are flagged")
    void detectsPunycode() {
        // xn--pypal-4ve.com renders as a Cyrillic look-alike of paypal.com.
        assertEquals(1.0, f("https://xn--pypal-4ve.com/login", "is_punycode"));
        assertEquals(0.0, f("https://paypal.com/login", "is_punycode"));
    }

    @Test
    @DisplayName("entropy measures character diversity")
    void entropyBehaviour() {
        assertEquals(0.0, UrlFeatureExtractor.shannonEntropy(""));
        // A single repeated character carries no information.
        assertEquals(0.0, UrlFeatureExtractor.shannonEntropy("aaaa"), 1e-9);
        // Four distinct characters over four positions is exactly 2 bits.
        assertEquals(2.0, UrlFeatureExtractor.shannonEntropy("abcd"), 1e-9);
        // Eight distinct characters over eight positions is exactly 3 bits.
        assertEquals(3.0, UrlFeatureExtractor.shannonEntropy("x7k2mq9v"), 1e-9);
        // A narrow alphabet scores low however long the string is: two symbols
        // over eight positions is 1 bit, well below the 3 bits above.
        assertEquals(1.0, UrlFeatureExtractor.shannonEntropy("aaaabbbb"), 1e-9);
        assertTrue(UrlFeatureExtractor.shannonEntropy("x7k2mq9v")
                        > UrlFeatureExtractor.shannonEntropy("aaaabbbb"),
                "A varied alphabet must score above a repetitive one");
    }

    @Test
    @DisplayName("entropy is order-invariant, so it cannot detect DGA hosts")
    void entropyCannotSeparateRandomFromPronounceable() {
        // This test exists to pin a limitation, not to celebrate a feature.
        //
        // Unigram Shannon entropy depends only on the multiset of characters, so
        // it is completely invariant to their order. "x7k2mq9v" looks machine
        // generated and "hdfcbank" is a real bank's domain, but both are eight
        // distinct characters over eight positions, so both score exactly 3.0
        // bits. host_entropy therefore measures character *diversity*, not
        // DGA-ness, and must not be described as detecting the latter.
        assertEquals(UrlFeatureExtractor.shannonEntropy("x7k2mq9v"),
                UrlFeatureExtractor.shannonEntropy("hdfcbank"), 1e-9,
                "Equal character diversity means equal unigram entropy");

        // Order-invariance stated directly: an anagram scores identically.
        assertEquals(UrlFeatureExtractor.shannonEntropy("hdfcbank"),
                UrlFeatureExtractor.shannonEntropy("kcabfdhn"), 1e-9,
                "Permuting the characters cannot change unigram entropy");

        // Separating pronounceable strings from random ones needs character
        // bigram/trigram statistics fitted to real domain names. That is a
        // 27th feature and is on the roadmap; if it is added, this test should
        // be replaced rather than deleted.
    }

    @Test
    @DisplayName("registrable domain handles two-label public suffixes")
    void registrableDomainHandlesCoIn() {
        assertEquals("irctc.co.in", UrlFeatureExtractor.registrableDomain("www.irctc.co.in"));
        assertEquals("uidai.gov.in", UrlFeatureExtractor.registrableDomain("resident.uidai.gov.in"));
        assertEquals("example.com", UrlFeatureExtractor.registrableDomain("a.b.example.com"));
        assertEquals("example.com", UrlFeatureExtractor.registrableDomain("example.com"));
    }

    @Test
    @DisplayName("host is parsed out of the URL, not guessed from the string")
    void parsesHostCorrectly() {
        // host_length must reflect the real host, so an @ trick cannot inflate it.
        double hostLen = f("http://trusted.com@evil.example.org/", "host_length");
        assertEquals((double) "evil.example.org".length(), hostLen,
                "The host after @ is the real destination");
    }

    // ---------------------------------------------------------------------
    // Regression: legitimate Indian bank domains were scored DANGEROUS.
    //
    // Observed on the running service: https://now.hdfc.bank.in returned 90 /
    // DANGEROUS / PHISHING_DETECTED. Four separate defects converged on it, and
    // each gets its own test below so a future change breaks the specific
    // assertion it invalidates.
    // ---------------------------------------------------------------------

    @Test
    @DisplayName("regression: bank.in is a public suffix, so the registrable domain includes the bank")
    void bankInIsATwoLabelSuffix() {
        // Was "bank.in", which made every brand allowlist entry unmatchable.
        assertEquals("hdfc.bank.in", UrlFeatureExtractor.registrableDomain("now.hdfc.bank.in"));
        assertEquals("hdfc.bank.in", UrlFeatureExtractor.registrableDomain("hdfc.bank.in"));
        assertEquals(2, UrlFeatureExtractor.publicSuffixLabelCount("now.hdfc.bank.in"));
        assertEquals(1, UrlFeatureExtractor.publicSuffixLabelCount("evil.example.com"));
    }

    @Test
    @DisplayName("regression: a brand must fill a token, not merely appear as a substring")
    void brandMatchingIsTokenBasedNotSubstringBased() {
        // These fired before: "praxis" contains "axis", "pineapple" contains
        // "apple". Both scored SUSPICIOUS on nothing but a coincidence of
        // spelling.
        assertEquals(0.0, f("https://praxis.com/", "brand_impersonation"));
        assertEquals(0.0, f("https://pineapple.co/", "brand_impersonation"));
        assertFalse(UrlFeatureExtractor.brandTokenPresent("praxis.com", "axis"));
        assertFalse(UrlFeatureExtractor.brandTokenPresent("pineapple.co", "apple"));

        // The attack patterns must survive the narrowing. A brand glued to a
        // recognised word inside one label still counts.
        assertTrue(UrlFeatureExtractor.brandTokenPresent("hdfcbank-secure.top", "hdfc"));
        assertTrue(UrlFeatureExtractor.brandTokenPresent("verifysbi.xyz", "sbi"));
        assertTrue(UrlFeatureExtractor.brandTokenPresent("sbi-secure-login.xyz", "sbi"));
        assertEquals(1.0, f("http://verifysbi.xyz/otp", "brand_impersonation"));
        assertEquals(1.0, f("http://hdfcbank-netbanking.co.in/login", "brand_impersonation"));
    }

    @Test
    @DisplayName("regression: an accredited registry suppresses the impersonation signal")
    void verifiedRegistrySuppressesBrandSignal() {
        // bank.in is restricted to RBI-licensed banks, so a brand token under it
        // is evidence of legitimacy rather than impersonation.
        assertEquals(0.0, f("https://now.hdfc.bank.in", "brand_impersonation"));
        assertTrue(UrlFeatureExtractor.isVerifiedRegistry("now.hdfc.bank.in"));
        assertTrue(UrlFeatureExtractor.isVerifiedRegistry("incometax.gov.in"));

        // co.in is sold to the public, so it must NOT be treated as accredited.
        // If this ever passes, the exemption has become a bypass.
        assertFalse(UrlFeatureExtractor.isVerifiedRegistry("hdfcbank-netbanking.co.in"));
        assertFalse(UrlFeatureExtractor.isVerifiedRegistry("random.example.com"));
    }

    @Test
    @DisplayName("regression: the registry exemption cannot be spoofed by prefixing")
    void verifiedSuffixMustBeTheActualSuffix() {
        // The single most dangerous way to get this wrong: reading "bank.in"
        // anywhere in the host instead of at the end. Here the real suffix is
        // .tk and the name is an outright forgery, so nothing is suppressed.
        assertFalse(UrlFeatureExtractor.isVerifiedRegistry("hdfc.bank.in.secure-login.tk"));
        assertEquals(1.0, f("http://hdfc.bank.in.secure-login.tk/kyc", "brand_impersonation"));
        assertEquals(1.0, f("http://hdfc.bank.in.secure-login.tk/kyc", "suspicious_tld"));
    }

    @Test
    @DisplayName("regression: public suffix labels are not subdomains and not keywords")
    void publicSuffixDoesNotInflateSubdomainOrKeywordCounts() {
        // num_subdomains counted every suffix label, so co.in and bank.in were
        // penalised for existing. now.hdfc.bank.in has exactly one subdomain.
        assertEquals(1.0, f("https://now.hdfc.bank.in", "num_subdomains"));
        assertEquals(1.0, f("https://www.sbi.co.in", "num_subdomains"));
        assertEquals(0.0, f("https://incometax.gov.in", "num_subdomains"));

        // "bank" in the suffix is not the registrant using urgency vocabulary.
        assertEquals(0.0, f("https://now.hdfc.bank.in", "num_sensitive_keywords"));
        assertEquals(0.0, f("https://retail.bank.in", "num_sensitive_keywords"));

        // But keywords outside the host still count, suffix stripping or not.
        assertTrue(f("https://retail.bank.in/login/verify-otp", "num_sensitive_keywords") >= 3,
                "Path keywords must survive the suffix substitution");
    }
}
