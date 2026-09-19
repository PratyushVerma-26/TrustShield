package com.trustshield.breach;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end tests over the real HTTP layer and a real H2 database.
 *
 * <p>Nothing here touches the network. That is the point: with both external
 * sources disabled by default, the bundled catalog still produces a genuine
 * {@code PASSWORD_EXPOSED} verdict, so the Wednesday demo cannot fail on
 * connectivity or a missing API key.
 */
@SpringBootTest
@AutoConfigureMockMvc
class BreachCheckIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    private static String passwordBody(String password) {
        // Built by hand rather than with an object mapper so the exact wire format
        // under test is visible in the test.
        return "{\"password\":\"" + password + "\",\"context\":\"integration-test\"}";
    }

    @Test
    @DisplayName("the context loads, which proves the JPA mappings and queries are valid")
    void contextLoads() {
        // Hibernate validates repository queries against the metamodel at startup,
        // so a broken derived query fails here rather than at request time.
        assertNotNull(mockMvc);
    }

    @Test
    @DisplayName("a known weak password is DANGEROUS offline, with no API key")
    void knownWeakPasswordIsExposedOffline() throws Exception {
        mockMvc.perform(post("/api/v1/breach/password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(passwordBody("password123")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.verdict.module").value("BREACH"))
                .andExpect(jsonPath("$.verdict.verdict").value("PASSWORD_EXPOSED"))
                .andExpect(jsonPath("$.verdict.threatLevel").value("DANGEROUS"))
                .andExpect(jsonPath("$.verdict.riskScore").value(
                        org.hamcrest.Matchers.greaterThanOrEqualTo(90)))
                .andExpect(jsonPath("$.kAnonymous").value(true))
                // SHA-1("password123") = CBFDAC6008F9CAB4083784CBD1874F76618D2A97
                .andExpect(jsonPath("$.bucketPrefix").value("CBFDA"))
                .andExpect(jsonPath("$.recommendation").value(
                        org.hamcrest.Matchers.containsString("Change this password now")));
    }

    /**
     * The response must not contain the password, nor its full hash, anywhere.
     *
     * <p>Asserted over the whole serialised body rather than field by field,
     * because the failure mode being guarded against is a field someone adds
     * later. The full digest is checked as well as the plaintext: echoing the
     * complete SHA-1 would hand back an offline-crackable value and quietly
     * destroy the k-anonymity property the endpoint advertises.
     */
    @Test
    @DisplayName("the response echoes neither the password nor its full hash")
    void responseNeverEchoesThePassword() throws Exception {
        String password = "uniqueSentinelValue4217";
        // Computed independently: SHA-1("uniqueSentinelValue4217"), upper hex.
        String fullHash = "9656EE0BF5746AFB86E879C5E0D797036669704F";

        MvcResult result = mockMvc.perform(post("/api/v1/breach/password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(passwordBody(password)))
                .andExpect(status().isOk())
                // Only the first 5 of those 40 characters may be disclosed.
                .andExpect(jsonPath("$.bucketPrefix").value("9656E"))
                .andReturn();

        String body = result.getResponse().getContentAsString();
        assertFalse(body.contains(password),
                "the password must never appear in a response body");
        assertFalse(body.contains(fullHash),
                "the full SHA-1 must never appear; only the 5-character bucket prefix");
        assertFalse(body.contains(fullHash.substring(5)),
                "the 35-character suffix is matched locally and must never be returned");
    }

    /**
     * Verifies that when all breach sources are unavailable, the verdict is reported as
     * UNKNOWN / INCONCLUSIVE with degraded=true rather than defaulting to clean/safe.
     */
    @Test
    @DisplayName("no sources reachable yields UNKNOWN, INCONCLUSIVE and degraded, never clean")
    void unreachableSourcesAreInconclusiveNotClean() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/v1/breach/password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(passwordBody("Xq7#vLm2$pRt9wZk")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.verdict.verdict").value("INCONCLUSIVE"))
                .andExpect(jsonPath("$.verdict.threatLevel").value("UNKNOWN"))
                .andExpect(jsonPath("$.verdict.degraded").value(true))
                .andExpect(jsonPath("$.strength.weaknessScore").value(0))
                .andReturn();

        String body = result.getResponse().getContentAsString();
        assertFalse(body.contains("This appears safe"),
                "a verdict produced with zero reachable sources must not be narrated as safe");
        assertFalse(body.contains("\"threatLevel\":\"SAFE\""),
                "the severity band a UI colour-codes on must not read SAFE either");
        assertTrue(body.contains("could not be completed"),
                "the user must be told the check did not complete");
    }

    /**
     * The structural sentence must not invent a finding.
     *
     * <p>{@code PasswordStrengthAnalyzer} appends a zero-penalty {@code NONE}
     * marker when no weakness fires, so the explanation used to count the list
     * naively and tell the user "1 structural observation(s) were made" about a
     * 104-bit random password. Only penalised entries are findings.
     */
    @Test
    @DisplayName("a structurally clean password is not reported as having an observation")
    void cleanStructureIsNotCountedAsAFinding() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/v1/breach/password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(passwordBody("Xq7#vLm2$pRt9wZk")))
                .andExpect(status().isOk())
                .andReturn();

        String body = result.getResponse().getContentAsString();
        assertTrue(body.contains("no structural weakness was detected"),
                "a password with zero penalised weaknesses must say so plainly");
        assertFalse(body.contains("1 structural"),
                "the zero-penalty NONE marker must not be counted as a finding");
        assertFalse(body.contains("observation(s)"),
                "user-facing prose must not use programmer plural notation");
    }

    /**
     * Structure is reported, and is also capped.
     *
     * <p>{@code Zx9!Qwerty} uses all four character classes and would pass most
     * naive strength meters, but it contains a keyboard walk and a common base
     * word, so structural analysis scores it 80. The service caps the structural
     * contribution at 60, which lands in {@code SUSPICIOUS} and deliberately stops
     * short of {@code DANGEROUS} (75).
     *
     * <p>That cap is the raise-only rule in the other direction: reaching
     * {@code DANGEROUS} requires <em>observed</em> exposure in a corpus, not a
     * prediction about how a password might fare. This password is not in the
     * bundled catalog, so nothing observed it.
     *
     * <p>When external corpora are unreachable but local structural analysis identifies
     * weaknesses, the score reflects observed structural evidence rather than defaulting to UNKNOWN.
     */
    @Test
    @DisplayName("structural analysis alone is capped below DANGEROUS")
    void structuralWeaknessesAreReportedButCapped() throws Exception {
        mockMvc.perform(post("/api/v1/breach/password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(passwordBody("Zx9!Qwerty")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.strength.characterClasses").value(4))
                .andExpect(jsonPath("$.strength.weaknessScore").value(80))
                .andExpect(jsonPath("$.strength.weaknesses[*].code")
                        .value(org.hamcrest.Matchers.hasItem("KEYBOARD_WALK")))
                .andExpect(jsonPath("$.strength.weaknesses[*].code")
                        .value(org.hamcrest.Matchers.hasItem("COMMON_BASE_WORD")))
                // 80 clamped to the 60 ceiling, which is SUSPICIOUS, not DANGEROUS.
                .andExpect(jsonPath("$.verdict.riskScore").value(60))
                .andExpect(jsonPath("$.verdict.threatLevel").value("SUSPICIOUS"))
                .andExpect(jsonPath("$.verdict.verdict").value("INCONCLUSIVE"));
    }

    @Test
    @DisplayName("a blank password is rejected without echoing it")
    void blankPasswordRejected() throws Exception {
        mockMvc.perform(post("/api/v1/breach/password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"password\":\"\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.message").value(
                        org.hamcrest.Matchers.containsString("password")));
    }

    /**
     * An email check the user did not authorise must not read as clean.
     *
     * <p>Same defect class as the password path, reached by a different route:
     * {@code notApplicable} scores 0 because nothing was sent, and deriving the
     * band from that score reported {@code SAFE} for an address that was never
     * looked up. The privacy refusal is the whole point of this path, so narrating
     * it as a clean result would be the worst available outcome.
     */
    @Test
    @DisplayName("an email check without acknowledgement refuses and transmits nothing")
    void emailRequiresAcknowledgement() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/v1/breach/email")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"someone@example.com\",\"acknowledged\":false}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.verdict.verdict").value("NOT_APPLICABLE"))
                .andExpect(jsonPath("$.verdict.threatLevel").value("UNKNOWN"))
                .andExpect(jsonPath("$.verdict.degraded").value(true))
                .andExpect(jsonPath("$.kAnonymous").value(false))
                .andExpect(jsonPath("$.breaches").isEmpty())
                .andReturn();

        String body = result.getResponse().getContentAsString();
        assertTrue(body.contains("Nothing was transmitted"));
        assertFalse(body.contains("This appears safe"),
                "refusing to run a check is not a finding of safety");
    }

    /**
     * The one source this endpoint has is unreachable without a key, so nothing is
     * learned and the band must say so. {@code degraded} alone was not enough: it
     * used to sit beside {@code threatLevel: SAFE}, and a UI reads the band.
     */
    @Test
    @DisplayName("an acknowledged email check still refuses without an API key")
    void emailNeedsApiKey() throws Exception {
        mockMvc.perform(post("/api/v1/breach/email")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"someone@example.com\",\"acknowledged\":true}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.verdict.verdict").value("SOURCE_UNAVAILABLE"))
                .andExpect(jsonPath("$.verdict.threatLevel").value("UNKNOWN"))
                .andExpect(jsonPath("$.verdict.degraded").value(true))
                .andExpect(jsonPath("$.kAnonymous").value(false));
    }

    @Test
    @DisplayName("a malformed email is rejected by validation")
    void malformedEmailRejected() throws Exception {
        mockMvc.perform(post("/api/v1/breach/email")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"not-an-email\",\"acknowledged\":true}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"));
    }

    @Test
    @DisplayName("checks are audited, and the audit trail holds no secrets")
    void historyRecordsChecksWithoutSecrets() throws Exception {
        mockMvc.perform(post("/api/v1/breach/password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(passwordBody("letmein")))
                .andExpect(status().isOk());

        MvcResult result = mockMvc.perform(get("/api/v1/breach/history"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andReturn();

        String body = result.getResponse().getContentAsString();
        assertFalse(body.contains("letmein"), "the audit trail must not hold the password");
        assertTrue(body.contains("PASSWORD"), "but it must record that a password was checked");
    }

    @Test
    @DisplayName("stats expose how often the system degraded, not just what it found")
    void statsIncludeDegradedCount() throws Exception {
        mockMvc.perform(get("/api/v1/breach/stats"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalChecks").exists())
                .andExpect(jsonPath("$.exposuresFound").exists())
                // A dashboard that hides this number overstates its own reliability.
                .andExpect(jsonPath("$.degradedChecks").exists())
                .andExpect(jsonPath("$.sources.offlineCatalogEntries").value(
                        org.hamcrest.Matchers.greaterThan(100)))
                .andExpect(jsonPath("$.sources.pwnedPasswordsRangeApiEnabled").value(false))
                .andExpect(jsonPath("$.sources.hibpAccountApiUsable").value(false));
    }

    @Test
    @DisplayName("the privacy card distinguishes the two endpoints")
    void privacyCardIsAccuratePerEndpoint() throws Exception {
        mockMvc.perform(get("/api/v1/breach/privacy"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.passwordCheck.kAnonymous").value(true))
                .andExpect(jsonPath("$.passwordCheck.worksOffline").value(true))
                .andExpect(jsonPath("$.emailCheck.kAnonymous").value(false))
                .andExpect(jsonPath("$.emailCheck.requiresAcknowledgement").value(true))
                .andExpect(jsonPath("$.emailCheck.stored").value(
                        org.hamcrest.Matchers.containsString("pseudonymisation")));
    }
}
