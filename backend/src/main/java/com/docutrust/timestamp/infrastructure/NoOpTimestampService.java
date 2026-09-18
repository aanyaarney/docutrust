package com.docutrust.timestamp.infrastructure;

import com.docutrust.timestamp.domain.TimestampResult;
import com.docutrust.timestamp.domain.TimestampService;

/**
 * Timestamping disabled.
 *
 * <p>The default, and the only implementation present in this build. It obtains
 * no token and says so explicitly, which is what makes signatures produced here
 * PAdES B-B rather than B-T.
 *
 * <p>This is not a stub pretending to work. It is a correctly-reporting
 * configuration: the one thing it must never do is return a fabricated token or
 * a local clock reading dressed up as attested time.
 */
public class NoOpTimestampService implements TimestampService {

    private static final String REASON =
            "No RFC 3161 Timestamp Authority is configured, so the time of signing "
                    + "cannot be attested by an independent party.";

    @Override
    public TimestampResult timestamp(byte[] signatureValue) {
        return TimestampResult.unavailable(REASON);
    }

    @Override
    public boolean isEnabled() {
        return false;
    }

    @Override
    public String providerName() {
        return "none";
    }
}
