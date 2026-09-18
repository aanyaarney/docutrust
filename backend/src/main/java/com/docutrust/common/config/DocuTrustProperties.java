package com.docutrust.common.config;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Externalised application configuration.
 *
 * <p>Every security-sensitive value here is bound from the environment and has
 * no usable default. A missing signing keystore or JWT secret must cause a
 * clear startup failure, never a silent fallback to something weak.
 */
@ConfigurationProperties(prefix = "docutrust")
public class DocuTrustProperties {

    private Upload upload = new Upload();
    private Jwt jwt = new Jwt();
    private Signing signing = new Signing();
    private Trust trust = new Trust();
    private Timestamp timestamp = new Timestamp();
    private Revocation revocation = new Revocation();
    private Storage storage = new Storage();
    private Cors cors = new Cors();
    private Demo demo = new Demo();
    private RateLimit rateLimit = new RateLimit();

    /**
     * Rate limiting.
     *
     * <p>Defaults are chosen to be invisible to ordinary use and painful to an
     * attacker. Ten login attempts a minute is far more than a person needs and
     * far less than credential stuffing requires. Thirty signing or verification
     * requests a minute per account covers any realistic interactive use while
     * capping the CPU one account can consume.
     */
    public static class RateLimit {
        private boolean enabled = true;

        /** Sustained login attempts per minute, per source address. */
        private long loginPerMinute = 10;
        /** Largest burst of login attempts tolerated. */
        private long loginBurst = 10;

        /** Sustained signing/verification requests per minute, per account. */
        private long expensivePerMinute = 30;
        /** Largest burst of signing/verification requests tolerated. */
        private long expensiveBurst = 15;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public long getLoginPerMinute() {
            return loginPerMinute;
        }

        public void setLoginPerMinute(long loginPerMinute) {
            this.loginPerMinute = loginPerMinute;
        }

        public long getLoginBurst() {
            return loginBurst;
        }

        public void setLoginBurst(long loginBurst) {
            this.loginBurst = loginBurst;
        }

        public long getExpensivePerMinute() {
            return expensivePerMinute;
        }

        public void setExpensivePerMinute(long expensivePerMinute) {
            this.expensivePerMinute = expensivePerMinute;
        }

        public long getExpensiveBurst() {
            return expensiveBurst;
        }

        public void setExpensiveBurst(long expensiveBurst) {
            this.expensiveBurst = expensiveBurst;
        }
    }

    public static class Upload {
        private int maxSizeMb = 25;
        private List<String> allowedContentTypes = List.of("application/pdf");

        public int getMaxSizeMb() {
            return maxSizeMb;
        }

        public void setMaxSizeMb(int maxSizeMb) {
            this.maxSizeMb = maxSizeMb;
        }

        public long maxSizeBytes() {
            return (long) maxSizeMb * 1024 * 1024;
        }

        public List<String> getAllowedContentTypes() {
            return allowedContentTypes;
        }

        public void setAllowedContentTypes(List<String> allowedContentTypes) {
            this.allowedContentTypes = allowedContentTypes;
        }
    }

    public static class Jwt {
        private String secret = "";
        private int ttlMinutes = 60;
        private String issuer = "docutrust";

        public String getSecret() {
            return secret;
        }

        public void setSecret(String secret) {
            this.secret = secret;
        }

        public int getTtlMinutes() {
            return ttlMinutes;
        }

        public void setTtlMinutes(int ttlMinutes) {
            this.ttlMinutes = ttlMinutes;
        }

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }
    }

    public static class Signing {
        private String provider = "pkcs12";
        private String pkcs12Path = "";
        private String pkcs12Password = "";
        private String pkcs12Alias = "";

        public String getProvider() {
            return provider;
        }

        public void setProvider(String provider) {
            this.provider = provider;
        }

        public String getPkcs12Path() {
            return pkcs12Path;
        }

        public void setPkcs12Path(String pkcs12Path) {
            this.pkcs12Path = pkcs12Path;
        }

        public String getPkcs12Password() {
            return pkcs12Password;
        }

        public void setPkcs12Password(String pkcs12Password) {
            this.pkcs12Password = pkcs12Password;
        }

        public String getPkcs12Alias() {
            return pkcs12Alias;
        }

        public void setPkcs12Alias(String pkcs12Alias) {
            this.pkcs12Alias = pkcs12Alias;
        }

        public boolean hasKeystore() {
            return pkcs12Path != null && !pkcs12Path.isBlank();
        }
    }

    public static class Trust {
        private String truststorePath = "";
        private String truststorePassword = "";

        public String getTruststorePath() {
            return truststorePath;
        }

        public void setTruststorePath(String truststorePath) {
            this.truststorePath = truststorePath;
        }

        public String getTruststorePassword() {
            return truststorePassword;
        }

        public void setTruststorePassword(String truststorePassword) {
            this.truststorePassword = truststorePassword;
        }

        public boolean hasTruststore() {
            return truststorePath != null && !truststorePath.isBlank();
        }
    }

    public static class Timestamp {
        private boolean enabled = false;
        private String url = "";

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }
    }

    public static class Revocation {
        private boolean enabled = false;
        private int timeoutSeconds = 10;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public int getTimeoutSeconds() {
            return timeoutSeconds;
        }

        public void setTimeoutSeconds(int timeoutSeconds) {
            this.timeoutSeconds = timeoutSeconds;
        }
    }

    public static class Storage {
        private String backend = "filesystem";
        private String filesystemRoot = "./.data/documents";
        private Minio minio = new Minio();

        public String getBackend() {
            return backend;
        }

        public void setBackend(String backend) {
            this.backend = backend;
        }

        public String getFilesystemRoot() {
            return filesystemRoot;
        }

        public void setFilesystemRoot(String filesystemRoot) {
            this.filesystemRoot = filesystemRoot;
        }

        public Minio getMinio() {
            return minio;
        }

        public void setMinio(Minio minio) {
            this.minio = minio;
        }

        public static class Minio {
            private String endpoint = "";
            private String accessKey = "";
            private String secretKey = "";
            private String bucket = "docutrust-documents";

            public String getEndpoint() {
                return endpoint;
            }

            public void setEndpoint(String endpoint) {
                this.endpoint = endpoint;
            }

            public String getAccessKey() {
                return accessKey;
            }

            public void setAccessKey(String accessKey) {
                this.accessKey = accessKey;
            }

            public String getSecretKey() {
                return secretKey;
            }

            public void setSecretKey(String secretKey) {
                this.secretKey = secretKey;
            }

            public String getBucket() {
                return bucket;
            }

            public void setBucket(String bucket) {
                this.bucket = bucket;
            }
        }
    }

    public static class Cors {
        private List<String> allowedOrigins = List.of("http://localhost:5173");

        public List<String> getAllowedOrigins() {
            return allowedOrigins;
        }

        public void setAllowedOrigins(List<String> allowedOrigins) {
            this.allowedOrigins = allowedOrigins;
        }
    }

    public static class Demo {
        private boolean seedEnabled = false;
        private String userEmail = "";
        private String userPassword = "";
        private String adminEmail = "";
        private String adminPassword = "";

        public boolean isSeedEnabled() {
            return seedEnabled;
        }

        public void setSeedEnabled(boolean seedEnabled) {
            this.seedEnabled = seedEnabled;
        }

        public String getUserEmail() {
            return userEmail;
        }

        public void setUserEmail(String userEmail) {
            this.userEmail = userEmail;
        }

        public String getUserPassword() {
            return userPassword;
        }

        public void setUserPassword(String userPassword) {
            this.userPassword = userPassword;
        }

        public String getAdminEmail() {
            return adminEmail;
        }

        public void setAdminEmail(String adminEmail) {
            this.adminEmail = adminEmail;
        }

        public String getAdminPassword() {
            return adminPassword;
        }

        public void setAdminPassword(String adminPassword) {
            this.adminPassword = adminPassword;
        }
    }

    public Upload getUpload() {
        return upload;
    }

    public void setUpload(Upload upload) {
        this.upload = upload;
    }

    public Jwt getJwt() {
        return jwt;
    }

    public void setJwt(Jwt jwt) {
        this.jwt = jwt;
    }

    public Signing getSigning() {
        return signing;
    }

    public void setSigning(Signing signing) {
        this.signing = signing;
    }

    public Trust getTrust() {
        return trust;
    }

    public void setTrust(Trust trust) {
        this.trust = trust;
    }

    public Timestamp getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Timestamp timestamp) {
        this.timestamp = timestamp;
    }

    public Revocation getRevocation() {
        return revocation;
    }

    public void setRevocation(Revocation revocation) {
        this.revocation = revocation;
    }

    public Storage getStorage() {
        return storage;
    }

    public void setStorage(Storage storage) {
        this.storage = storage;
    }

    public Cors getCors() {
        return cors;
    }

    public void setCors(Cors cors) {
        this.cors = cors;
    }

    public Demo getDemo() {
        return demo;
    }

    public void setDemo(Demo demo) {
        this.demo = demo;
    }

    public RateLimit getRateLimit() {
        return rateLimit;
    }

    public void setRateLimit(RateLimit rateLimit) {
        this.rateLimit = rateLimit;
    }
}
