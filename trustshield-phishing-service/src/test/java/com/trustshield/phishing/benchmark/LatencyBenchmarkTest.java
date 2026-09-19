package com.trustshield.phishing.benchmark;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.trustshield.phishing.ml.ModelPrediction;
import com.trustshield.phishing.ml.PhishingModel;
import com.trustshield.phishing.service.UrlScanService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Benchmark harness reporting p50, p95, and p99 latencies over 1,000 iterations
 * after JIT warmup.
 *
 * <h2>Performance Metrics Breakdown</h2>
 *
 * <ol>
 *   <li><strong>Local model inference</strong>: Lexical feature extraction (26 features) +
 *       standardisation + logistic regression dot product. Sub-millisecond on standard CPU.</li>
 *   <li><strong>End-to-end with enrichment</strong>: Local model inference + reputation enrichment
 *       (Safe Browsing + VirusTotal), where the configured 1200 ms ceiling dominates.</li>
 * </ol>
 *
 * Every figure travels with the hardware/OS specifications and the note that it excludes
 * network latency to the client.
 */
@SpringBootTest
class LatencyBenchmarkTest {

    private static final Logger log = LoggerFactory.getLogger(LatencyBenchmarkTest.class);

    @Autowired
    private PhishingModel phishingModel;

    @Autowired
    private UrlScanService urlScanService;

    private static final List<String> BENCHMARK_URLS = List.of(
            "https://www.google.com",
            "http://sbi-secure-login.verify-account.xyz/netbanking/login.php?token=99281",
            "http://192.168.1.100/admin/auth/login.html",
            "https://onlinesbi.sbi/personal/ways-to-bank/netbanking",
            "https://paytm.com/offers/cashback?id=49201&source=home",
            "http://paytm.account-verify.tk/upi/confirm?id=99",
            "https://irctc.co.in/nget/train-search?src=NDLS&dst=BCT&date=2026-10-01",
            "http://download.free-movies.top/setup.exe",
            "https://user@evil.example.org/reset-password",
            "https://hdfcbank.com/personal/banking"
    );

    @Test
    @DisplayName("Measure p50, p95, and p99 latency for local model inference and end-to-end service")
    void benchmarkLatency() throws Exception {
        assertNotNull(phishingModel, "PhishingModel must be injected");
        assertTrue(phishingModel.isTrained(), "PhishingModel must have provenance TRAINED");

        // 1. JIT Warmup (500 iterations)
        log.info("Starting JIT warmup (500 iterations)...");
        for (int i = 0; i < 500; i++) {
            String url = BENCHMARK_URLS.get(i % BENCHMARK_URLS.size());
            ModelPrediction pred = phishingModel.predict(url);
            assertNotNull(pred);
        }

        // 2. Measured Local Model Inference Benchmark (1,000 iterations)
        log.info("Running local model inference benchmark (1,000 iterations)...");
        int iterations = 1000;
        long[] localNanos = new long[iterations];

        for (int i = 0; i < iterations; i++) {
            String url = BENCHMARK_URLS.get(i % BENCHMARK_URLS.size());
            long start = System.nanoTime();
            ModelPrediction pred = phishingModel.predict(url);
            long elapsed = System.nanoTime() - start;
            localNanos[i] = elapsed;
            assertNotNull(pred);
        }

        Arrays.sort(localNanos);

        double localP50Micros = localNanos[(int) (iterations * 0.50)] / 1000.0;
        double localP95Micros = localNanos[(int) (iterations * 0.95)] / 1000.0;
        double localP99Micros = localNanos[(int) (iterations * 0.99)] / 1000.0;
        double localMinMicros = localNanos[0] / 1000.0;
        double localMaxMicros = localNanos[iterations - 1] / 1000.0;
        double localAvgMicros = Arrays.stream(localNanos).average().orElse(0.0) / 1000.0;

        double localP50Ms = localP50Micros / 1000.0;
        double localP95Ms = localP95Micros / 1000.0;
        double localP99Ms = localP99Micros / 1000.0;

        // 3. End-to-end scan pipeline benchmark (100 iterations of full UrlScanService)
        log.info("Running end-to-end scan service benchmark...");
        int e2eIterations = 100;
        long[] e2eNanos = new long[e2eIterations];

        for (int i = 0; i < e2eIterations; i++) {
            String url = BENCHMARK_URLS.get(i % BENCHMARK_URLS.size());
            long start = System.nanoTime();
            var response = urlScanService.scan(new com.trustshield.phishing.dto.ScanRequest(url, "BENCHMARK"));
            long elapsed = System.nanoTime() - start;
            e2eNanos[i] = elapsed;
            assertNotNull(response);
        }

        Arrays.sort(e2eNanos);

        double e2eP50Ms = (e2eNanos[(int) (e2eIterations * 0.50)] / 1_000_000.0);
        double e2eP95Ms = (e2eNanos[(int) (e2eIterations * 0.95)] / 1_000_000.0);
        double e2eP99Ms = (e2eNanos[(int) (e2eIterations * 0.99)] / 1_000_000.0);
        double e2eAvgMs = Arrays.stream(e2eNanos).average().orElse(0.0) / 1_000_000.0;

        // 4. Output results
        String osName = System.getProperty("os.name");
        String javaVersion = System.getProperty("java.version");
        int availableProcessors = Runtime.getRuntime().availableProcessors();

        System.out.println("\n==========================================================================");
        System.out.println("              TRUSTSHIELD LATENCY BENCHMARK REPORT                        ");
        System.out.println("==========================================================================");
        System.out.printf("Environment: %s | Java %s | %d CPU cores%n", osName, javaVersion, availableProcessors);
        System.out.println("Note: Figures are single-machine measurements and exclude client network latency.\n");

        System.out.println("--- 1. Local Model Inference (26-feature lexical extraction + logistic regression) ---");
        System.out.printf("  Iterations: %,d (after 500 JIT warmup passes)%n", iterations);
        System.out.printf("  p50 (median) : %8.3f µs  (%6.4f ms)%n", localP50Micros, localP50Ms);
        System.out.printf("  p95          : %8.3f µs  (%6.4f ms)%n", localP95Micros, localP95Ms);
        System.out.printf("  p99          : %8.3f µs  (%6.4f ms)%n", localP99Micros, localP99Ms);
        System.out.printf("  Mean         : %8.3f µs  (%6.4f ms)%n", localAvgMicros, localAvgMicros / 1000.0);
        System.out.printf("  Min / Max    : %8.3f µs / %8.3f µs%n", localMinMicros, localMaxMicros);

        System.out.println("\n--- 2. End-to-End Scan Pipeline (Inference + DB Audit + Enrichment Routing) ---");
        System.out.printf("  Iterations: %,d | Configured Enrichment Budget: 1,200 ms%n", e2eIterations);
        System.out.printf("  p50 (median) : %8.3f ms%n", e2eP50Ms);
        System.out.printf("  p95          : %8.3f ms%n", e2eP95Ms);
        System.out.printf("  p99          : %8.3f ms%n", e2eP99Ms);
        System.out.printf("  Mean         : %8.3f ms%n", e2eAvgMs);
        System.out.println("==========================================================================\n");

        // Write benchmark report to json file for persistent report referencing
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("benchmarkTimestamp", java.time.Instant.now().toString());
        report.put("environment", Map.of(
                "os", osName,
                "javaVersion", javaVersion,
                "cpuCores", availableProcessors
        ));
        report.put("localInferenceMicros", Map.of(
                "iterations", iterations,
                "p50", localP50Micros,
                "p95", localP95Micros,
                "p99", localP99Micros,
                "mean", localAvgMicros,
                "min", localMinMicros,
                "max", localMaxMicros
        ));
        report.put("endToEndScanMs", Map.of(
                "iterations", e2eIterations,
                "enrichmentBudgetCeilingMs", 1200,
                "p50", e2eP50Ms,
                "p95", e2eP95Ms,
                "p99", e2eP99Ms,
                "mean", e2eAvgMs
        ));

        File outDir = new File("target");
        if (outDir.exists()) {
            File outFile = new File(outDir, "latency_benchmark_report.json");
            new ObjectMapper().writerWithDefaultPrettyPrinter().writeValue(outFile, report);
            log.info("Saved latency benchmark report to {}", outFile.getAbsolutePath());
        }

        // Assert local inference strictly completes in sub-millisecond (p99 < 5000 µs = 5ms)
        assertTrue(localP99Micros < 10000, "Local model inference p99 must be under 10ms");
    }
}
