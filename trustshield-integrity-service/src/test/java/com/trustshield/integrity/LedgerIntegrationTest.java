package com.trustshield.integrity;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
class LedgerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private com.trustshield.integrity.repository.LedgerEntryRecordRepository repository;

    @org.junit.jupiter.api.BeforeEach
    void setUp() {
        repository.deleteAll();
    }

    @Test
    @DisplayName("append, head, entry, and verify endpoints function end-to-end")
    void ledgerEndToEndWorkflow() throws Exception {
        // 1. Commit entry 0 via /api/v1/integrity/append
        String req0 = """
                {
                    "incidentId": "INC-INT-001",
                    "module": "PHISHING",
                    "canonicalVerdictJson": "{\\"score\\":15,\\"level\\":\\"LOW\\"}"
                }
                """;

        mockMvc.perform(post("/api/v1/integrity/append")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(req0))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sequenceNumber").value(0))
                .andExpect(jsonPath("$.entryHash").exists())
                .andExpect(jsonPath("$.previousChainHash").value("0000000000000000000000000000000000000000000000000000000000000000"))
                .andExpect(jsonPath("$.chainHash").exists());

        // 2. Commit entry 1 via alias /api/v1/ledger/append
        String req1 = """
                {
                    "incidentId": "INC-INT-002",
                    "module": "DEEPFAKE",
                    "canonicalVerdictJson": "{\\"score\\":92,\\"level\\":\\"DANGEROUS\\"}"
                }
                """;

        mockMvc.perform(post("/api/v1/ledger/append")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(req1))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sequenceNumber").value(1))
                .andExpect(jsonPath("$.previousChainHash").exists());

        // 3. Query head via GET /api/v1/integrity/head
        mockMvc.perform(get("/api/v1/integrity/head"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sequenceNumber").value(1))
                .andExpect(jsonPath("$.headChainHash").exists())
                .andExpect(jsonPath("$.ed25519SignatureHex").exists())
                .andExpect(jsonPath("$.publicKeyBase64").exists());

        // 4. Query entry 0 via GET /api/v1/integrity/entry/0
        mockMvc.perform(get("/api/v1/integrity/entry/0"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sequenceNumber").value(0))
                .andExpect(jsonPath("$.module").value("PHISHING"));

        // 5. Query entries via GET /api/v1/integrity/entries
        mockMvc.perform(get("/api/v1/integrity/entries"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(2));

        // 6. Verify hash chain via GET /api/v1/integrity/verify
        mockMvc.perform(get("/api/v1/integrity/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.totalEntriesChecked").value(2))
                .andExpect(jsonPath("$.signatureValid").value(true));

        // 7. Query info via GET /api/v1/integrity/info
        mockMvc.perform(get("/api/v1/integrity/info"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.service").value("trustshield-integrity-service"))
                .andExpect(jsonPath("$.port").value(8087))
                .andExpect(jsonPath("$.genesisHash").exists());
    }
}
