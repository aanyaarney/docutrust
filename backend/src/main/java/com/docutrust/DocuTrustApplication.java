package com.docutrust;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * DocuTrust — Enterprise Digital Signature, Document Integrity and Tamper
 * Detection Platform.
 *
 * <p>A modular monolith: one deployable process partitioned into feature
 * modules ({@code document}, {@code signature}, {@code verification},
 * {@code certificate}, {@code audit}, {@code storage}, {@code security}).
 * See {@code docs/ADR/ADR-001-modular-monolith.md}.
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class DocuTrustApplication {

    public static void main(String[] args) {
        SpringApplication.run(DocuTrustApplication.class, args);
    }
}
