package com.docutrust.common.observability;

import java.time.Duration;

import org.springframework.stereotype.Component;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;

import com.docutrust.verification.domain.VerificationVerdict;

/**
 * Application metrics.
 *
 * <h2>Label discipline</h2>
 * Every label here is low-cardinality and drawn from a closed set — an enum name,
 * or nothing at all. Filenames, document identifiers, user identifiers and
 * verification identifiers are deliberately <strong>never</strong> used as
 * labels.
 *
 * <p>Two reasons, and both matter. Unbounded label values create a new time
 * series per distinct value, which is the standard way to bring down a metrics
 * backend. And a metrics system is usually far less access-controlled than the
 * application database, so a document called
 * {@code acquisition-of-competitor.pdf} appearing in a metric name leaks
 * something confidential to everyone with a dashboard
 * (specification section 38).
 */
@Component
public class DocuTrustMetrics {

    private final Counter documentsUploaded;
    private final Counter documentsSigned;
    private final Counter signingFailures;
    private final Counter tamperingDetected;
    private final Timer signatureDuration;
    private final Timer verificationDuration;
    private final MeterRegistry registry;

    public DocuTrustMetrics(MeterRegistry registry) {
        this.registry = registry;

        this.documentsUploaded = Counter.builder("documents_uploaded_total")
                .description("Documents accepted for storage")
                .register(registry);

        this.documentsSigned = Counter.builder("documents_signed_total")
                .description("Signatures successfully applied")
                .register(registry);

        this.signingFailures = Counter.builder("signing_failed_total")
                .description("Signing attempts that failed")
                .register(registry);

        this.tamperingDetected = Counter.builder("tampering_detected_total")
                .description("Verifications that found cryptographically proven modification")
                .register(registry);

        this.signatureDuration = Timer.builder("signature_duration_seconds")
                .description("Time taken to apply a signature")
                .register(registry);

        this.verificationDuration = Timer.builder("verification_duration_seconds")
                .description("Time taken to verify a document")
                .register(registry);
    }

    public void recordUpload() {
        documentsUploaded.increment();
    }

    public void recordSigned(Duration elapsed) {
        documentsSigned.increment();
        signatureDuration.record(elapsed);
    }

    public void recordSigningFailure() {
        signingFailures.increment();
    }

    /**
     * Records a verification outcome.
     *
     * <p>The verdict is an enum, so {@code verification_total} has exactly one
     * series per possible outcome and cannot grow with traffic.
     */
    public void recordVerification(VerificationVerdict verdict, boolean tampered, Duration elapsed) {
        Counter.builder("verification_total")
                .description("Verifications performed, by outcome")
                .tag("verdict", verdict.name())
                .register(registry)
                .increment();

        if (verdict.isFailure()) {
            Counter.builder("verification_failed_total")
                    .description("Verifications returning a failing verdict")
                    .tag("verdict", verdict.name())
                    .register(registry)
                    .increment();
        }

        if (tampered) {
            tamperingDetected.increment();
        }

        verificationDuration.record(elapsed);
    }
}
