// SPDX-License-Identifier: LGPL-2.1-or-later
package io.librescrs.dss;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.source.TLSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import jakarta.annotation.PreDestroy;

import java.io.File;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

@Component
public class TrustConfigManager {

    private static final Logger log = LoggerFactory.getLogger(TrustConfigManager.class);

    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");
    private static final Set<String> BLOCKED_HOSTS = Set.of(
            "169.254.169.254",          // AWS / Azure instance metadata service (IMDS)
            "100.100.100.200",          // Aliyun metadata
            "metadata.google.internal", // GCP metadata
            "fd00::ec2"                 // AWS IPv6 metadata
    );

    /**
     * Validates a trust-list URL before it is handed to the EU DSS HTTP loaders.
     * Rejects non-http(s) schemes, private / loopback / link-local / any-local
     * addresses, and well-known cloud metadata endpoints (SSRF hardening).
     *
     * @throws IllegalArgumentException if the URL is null, malformed, uses a
     *     disallowed scheme, or resolves to a blocked/internal address.
     */
    static void validateTrustListUrl(String url) {
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("Trust list URL is empty");
        }
        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Trust list URL is malformed: " + url, e);
        }
        String scheme = uri.getScheme();
        if (scheme == null || !ALLOWED_SCHEMES.contains(scheme.toLowerCase())) {
            throw new IllegalArgumentException(
                    "Trust list URL must use http or https scheme: " + url);
        }
        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException("Trust list URL has no host: " + url);
        }
        // Cheap defensive check: hostnames should not contain path-traversal-ish
        // characters. Unlikely to matter given URI parsing, but cheap.
        if (host.contains("/") || host.contains("\\") || host.contains("..")) {
            throw new IllegalArgumentException(
                    "Trust list URL host contains illegal characters: " + host);
        }
        String hostLower = host.toLowerCase();
        if (BLOCKED_HOSTS.contains(hostLower)) {
            throw new IllegalArgumentException(
                    "Trust list URL host is blocked: " + host);
        }
        try {
            for (InetAddress addr : InetAddress.getAllByName(host)) {
                if (addr.isAnyLocalAddress() || addr.isLoopbackAddress()
                        || addr.isLinkLocalAddress() || addr.isSiteLocalAddress()) {
                    throw new IllegalArgumentException(
                            "Trust list URL host resolves to a private/local address: "
                                    + host + " -> " + addr.getHostAddress());
                }
                String addrLower = addr.getHostAddress().toLowerCase();
                if (BLOCKED_HOSTS.contains(addrLower)) {
                    throw new IllegalArgumentException(
                            "Trust list URL host resolves to a blocked address: "
                                    + host + " -> " + addrLower);
                }
            }
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException(
                    "Trust list URL host cannot be resolved: " + host, e);
        }
    }

    private final ExecutorService executor = Executors.newCachedThreadPool(r -> {
        var t = new Thread(r, "tl-loader");
        t.setDaemon(true);
        return t;
    });

    private volatile TrustedListsCertificateSource trustedListsCertificateSource;
    private volatile boolean crlEnabled;
    private volatile boolean ocspEnabled;
    private volatile boolean configured;

    @SuppressWarnings("unchecked")
    public void configure(Map<String, Object> config) {
        var trustedLists = (List<Map<String, Object>>) config.getOrDefault("trustedLists", List.of());
        String cacheDirectory = (String) config.getOrDefault("cacheDirectory", System.getProperty("java.io.tmpdir") + "/dss-tsl-cache");
        crlEnabled = Boolean.TRUE.equals(config.get("crlEnabled"));
        ocspEnabled = Boolean.TRUE.equals(config.get("ocspEnabled"));

        var cacheDir = new File(cacheDirectory);
        if (!cacheDir.exists()) {
            cacheDir.mkdirs();
        }

        var cacheLoader = new FileCacheDataLoader();
        cacheLoader.setCacheExpirationTime(0);
        cacheLoader.setDataLoader(new CommonsDataLoader());
        cacheLoader.setFileCacheDirectory(cacheDir);

        var tlSources = new ArrayList<TLSource>();
        var lotlSources = new ArrayList<LOTLSource>();
        var eagerJobs = new ArrayList<TLValidationJob>();
        var lazyJobs = new ArrayList<TLValidationJob>();

        trustedListsCertificateSource = new TrustedListsCertificateSource();

        for (var entry : trustedLists) {
            String url = (String) entry.get("url");
            boolean isLotl = Boolean.TRUE.equals(entry.get("lotl"));
            boolean isEager = Boolean.TRUE.equals(entry.get("eager"));

            // SSRF hardening: reject internal/private/metadata URLs before
            // handing them to the EU DSS HTTP loader.
            validateTrustListUrl(url);

            var job = new TLValidationJob();
            job.setTrustedListCertificateSource(trustedListsCertificateSource);
            job.setListOfTrustedListSources(new LOTLSource[0]);
            job.setTrustedListSources(new TLSource[0]);

            if (isLotl) {
                var lotlSource = new LOTLSource();
                lotlSource.setUrl(url);
                lotlSource.setCertificateSource(new TrustedListsCertificateSource());
                job.setListOfTrustedListSources(lotlSource);
                lotlSources.add(lotlSource);
            } else {
                var tlSource = new TLSource();
                tlSource.setUrl(url);
                job.setTrustedListSources(tlSource);
                tlSources.add(tlSource);
            }

            job.setOfflineDataLoader(cacheLoader);
            job.setOnlineDataLoader(cacheLoader);

            if (isEager) {
                eagerJobs.add(job);
            } else {
                lazyJobs.add(job);
            }
        }

        // Load eager sources synchronously
        for (var job : eagerJobs) {
            try {
                log.info("Loading trusted list (eager)...");
                job.onlineRefresh();
                log.info("Trusted list loaded successfully");
            } catch (Exception e) {
                log.warn("Failed to load eager trusted list: {}", e.getMessage());
            }
        }

        // Load lazy sources in background daemon threads
        for (var job : lazyJobs) {
            executor.submit(() -> {
                try {
                    log.info("Loading trusted list (lazy, background)...");
                    job.onlineRefresh();
                    log.info("Background trusted list loaded successfully");
                } catch (Exception e) {
                    log.warn("Failed to load lazy trusted list: {}", e.getMessage());
                }
            });
        }

        configured = true;
        log.info("Trust configuration applied: {} TL sources, {} LOTL sources, CRL={}, OCSP={}",
                tlSources.size(), lotlSources.size(), crlEnabled, ocspEnabled);
    }

    public CommonCertificateVerifier getCertificateVerifier(boolean allowExpiredCert) {
        var verifier = new CommonCertificateVerifier();

        if (configured) {
            verifier.setTrustedCertSources(trustedListsCertificateSource);

            if (crlEnabled) {
                verifier.setCrlSource(new OnlineCRLSource());
            }
            if (ocspEnabled) {
                verifier.setOcspSource(new OnlineOCSPSource());
            }

            verifier.setAIASource(new DefaultAIASource());

            // Alerting: log missing revocation data, throw on revoked, log on expired
            verifier.setAlertOnMissingRevocationData(new LogOnStatusAlert());
            verifier.setAlertOnRevokedCertificate(new ExceptionOnStatusAlert());
        }

        if (allowExpiredCert) {
            verifier.setAlertOnExpiredCertificate(new LogOnStatusAlert());
        }

        return verifier;
    }

    public boolean isConfigured() {
        return configured;
    }

    @PreDestroy
    public void shutdown() {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
