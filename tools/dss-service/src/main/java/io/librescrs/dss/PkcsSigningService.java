// SPDX-License-Identifier: LGPL-2.1-or-later
package io.librescrs.dss;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.common.SecureContainerHandlerBuilder;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.token.Pkcs11SignatureToken;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.springframework.stereotype.Service;

import java.security.KeyStore;
import java.util.Map;

@Service
public class PkcsSigningService {

    private final TrustConfigManager trustConfigManager;

    public PkcsSigningService(TrustConfigManager trustConfigManager) {
        this.trustConfigManager = trustConfigManager;

        // Increase default ASiC/ZIP container limits (anti-zip-bomb protection).
        // Defaults are too restrictive: 1000 files, 1MB threshold, 100x ratio.
        var builder = new SecureContainerHandlerBuilder();
        builder.setMaxAllowedFilesAmount(100_000);
        builder.setThreshold(256_000_000L); // 256 MB decompressed
        builder.setMaxCompressionRatio(1000);
        ZipUtils.getInstance().setZipContainerHandlerBuilder(builder);
    }

    @SuppressWarnings("unchecked")
    public byte[] sign(byte[] docBytes, String fileName, Map<String, Object> metadata) throws Exception {
        String format = (String) metadata.get("format");
        String level = (String) metadata.get("level");
        String pkcs11Path = (String) metadata.get("pkcs11ModulePath");
        String pin = (String) metadata.get("pin");
        metadata.remove("pin");
        String keyAlias = (String) metadata.get("keyAlias");

        // Slot ID is required — the caller (C++ side) determines which
        // PKCS#11 slot contains the user's selected certificate/key.
        int slotIndex = ((Number) metadata.get("slotIndex")).intValue();

        var doc = new InMemoryDocument(docBytes);
        if (fileName != null && !fileName.isEmpty()) {
            doc.setName(fileName);
        }

        Boolean allowExpired = (Boolean) metadata.getOrDefault("allowExpiredCertificate", false);
        var certVerifier = trustConfigManager.getCertificateVerifier(allowExpired);

        try (var token = new Pkcs11SignatureToken(pkcs11Path,
                new KeyStore.PasswordProtection(pin.toCharArray()), slotIndex)) {

            var keys = token.getKeys();
            if (keys.isEmpty()) {
                throw new RuntimeException("No signing keys found in PKCS#11 token (slot " + slotIndex + ")");
            }

            var key = keys.get(0);
            if (keyAlias != null && !keyAlias.isEmpty()) {
                key = keys.stream()
                        .filter(k -> keyAlias.equals(k.getCertificate().getDSSIdAsString()))
                        .findFirst()
                        .orElse(key);
            }

            DSSDocument signed;
            switch (format) {
                case "PAdES" -> {
                    var params = new PAdESSignatureParameters();
                    params.setSignatureLevel(parseLevel("PAdES", level));
                    params.setSigningCertificate(key.getCertificate());
                    params.setCertificateChain(key.getCertificateChain());
                    params.setContentSize(contentSizeForLevel(level));

                    configureVisualSignature(params, metadata, docBytes);

                    var service = new PAdESService(certVerifier);
                    configureTSA(service, metadata);

                    var toSign = service.getDataToSign(doc, params);
                    var sig = token.sign(toSign, params.getDigestAlgorithm(), key);
                    signed = service.signDocument(doc, params, sig);
                }
                case "CAdES" -> {
                    var params = new CAdESSignatureParameters();
                    params.setSignatureLevel(parseLevel("CAdES", level));
                    params.setSignaturePackaging(SignaturePackaging.DETACHED);
                    params.setSigningCertificate(key.getCertificate());
                    params.setCertificateChain(key.getCertificateChain());

                    var service = new CAdESService(certVerifier);
                    configureTSA(service, metadata);

                    var toSign = service.getDataToSign(doc, params);
                    var sig = token.sign(toSign, params.getDigestAlgorithm(), key);
                    signed = service.signDocument(doc, params, sig);
                }
                case "ASiC_E" -> {
                    var params = new ASiCWithCAdESSignatureParameters();
                    params.aSiC().setContainerType(ASiCContainerType.ASiC_E);
                    params.setSignatureLevel(parseLevel("CAdES", level));
                    params.setSigningCertificate(key.getCertificate());
                    params.setCertificateChain(key.getCertificateChain());

                    var service = new ASiCWithCAdESService(certVerifier);
                    configureTSA(service, metadata);

                    var toSign = service.getDataToSign(doc, params);
                    var sig = token.sign(toSign, params.getDigestAlgorithm(), key);
                    signed = service.signDocument(doc, params, sig);
                }
                case "XAdES" -> {
                    String packaging = (String) metadata.getOrDefault("packaging", "ENVELOPED");
                    var params = new XAdESSignatureParameters();
                    params.setSignatureLevel(parseLevel("XAdES", level));
                    params.setSignaturePackaging(
                        "DETACHED".equals(packaging)
                            ? SignaturePackaging.DETACHED
                            : SignaturePackaging.ENVELOPED
                    );
                    params.setSigningCertificate(key.getCertificate());
                    params.setCertificateChain(key.getCertificateChain());

                    var service = new XAdESService(certVerifier);
                    configureTSA(service, metadata);

                    var toSign = service.getDataToSign(doc, params);
                    var sig = token.sign(toSign, params.getDigestAlgorithm(), key);
                    signed = service.signDocument(doc, params, sig);
                }
                case "JAdES" -> {
                    var params = new JAdESSignatureParameters();
                    params.setSignatureLevel(parseLevel("JAdES", level));
                    params.setSignaturePackaging(SignaturePackaging.DETACHED);
                    params.setSigDMechanism(eu.europa.esig.dss.enumerations.SigDMechanism.OBJECT_ID_BY_URI_HASH);
                    params.setSigningCertificate(key.getCertificate());
                    params.setCertificateChain(key.getCertificateChain());

                    var service = new JAdESService(certVerifier);
                    configureTSA(service, metadata);

                    var toSign = service.getDataToSign(doc, params);
                    var sig = token.sign(toSign, params.getDigestAlgorithm(), key);
                    signed = service.signDocument(doc, params, sig);
                }
                default -> throw new IllegalArgumentException("Unsupported format: " + format);
            }

            try (var is = signed.openStream()) {
                return is.readAllBytes();
            }
        }
    }

    private SignatureLevel parseLevel(String format, String level) {
        return SignatureLevel.valueByName(format + "_BASELINE_" + level.replace("B_", ""));
    }

    // PAdES signature container size (bytes). Higher levels embed timestamps, CRLs,
    // and OCSP responses, requiring larger reserved space in the PDF signature field.
    private int contentSizeForLevel(String level) {
        return switch (level) {
            case "B_LT", "B_LTA" -> 32768;
            case "B_T" -> 16384;
            default -> 9472;
        };
    }

    @SuppressWarnings("unchecked")
    private void configureVisualSignature(PAdESSignatureParameters params, Map<String, Object> metadata,
                                          byte[] docBytes) {
        var visual = (Map<String, Object>) metadata.get("visual");
        if (visual == null) return;

        var imageParams = new SignatureImageParameters();

        // Position — DSS uses 1-based page numbers.
        // page=-1 means last page; resolve by counting pages in the PDF.
        var fieldParams = imageParams.getFieldParameters();
        int page = ((Number) visual.getOrDefault("page", -1)).intValue();
        if (page <= 0) {
            // Count pages to resolve "last page"
            try (var pdfReader = new com.lowagie.text.pdf.PdfReader(docBytes)) {
                page = pdfReader.getNumberOfPages();
            } catch (Exception e) {
                page = 1; // fallback to first page
            }
        }
        fieldParams.setPage(page);
        fieldParams.setOriginX(((Number) visual.getOrDefault("x", 0)).floatValue());
        fieldParams.setOriginY(((Number) visual.getOrDefault("y", 0)).floatValue());
        fieldParams.setWidth(((Number) visual.getOrDefault("width", 200)).floatValue());
        fieldParams.setHeight(((Number) visual.getOrDefault("height", 50)).floatValue());

        // Text content
        var textParams = new SignatureImageTextParameters();
        String preformatted = (String) visual.getOrDefault("text", "");
        if (preformatted.isEmpty()) {
            // Backward compat: build text from individual fields
            String signerName = (String) visual.getOrDefault("signerName", "");
            String reason = (String) visual.getOrDefault("reason", "");
            String location = (String) visual.getOrDefault("location", "");

            var sb = new StringBuilder();
            if (!signerName.isEmpty()) sb.append("Digitally signed by: ").append(signerName).append("\n");
            sb.append("Date: ").append(java.time.LocalDateTime.now()
                    .format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
            if (!reason.isEmpty()) sb.append("\nReason: ").append(reason);
            if (!location.isEmpty()) sb.append("\nLocation: ").append(location);
            preformatted = sb.toString();
        }
        textParams.setText(preformatted);
        textParams.setTextWrapping(eu.europa.esig.dss.enumerations.TextWrapping.FILL_BOX);
        imageParams.setTextParameters(textParams);

        params.setImageParameters(imageParams);
    }

    @SuppressWarnings("unchecked")
    private void configureTSA(Object service, Map<String, Object> request) {
        var tsaMap = (Map<String, Object>) request.get("tsa");
        if (tsaMap == null) return;
        String tsaUrl = (String) tsaMap.get("url");
        if (tsaUrl == null || tsaUrl.isEmpty()) return;

        var tspSource = new OnlineTSPSource(tsaUrl);
        if (service instanceof PAdESService ps) {
            ps.setTspSource(tspSource);
        } else if (service instanceof CAdESService cs) {
            cs.setTspSource(tspSource);
        } else if (service instanceof ASiCWithCAdESService as) {
            as.setTspSource(tspSource);
        } else if (service instanceof XAdESService xs) {
            xs.setTspSource(tspSource);
        } else if (service instanceof JAdESService js) {
            js.setTspSource(tspSource);
        }
    }
}
