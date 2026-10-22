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
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.signature.AbstractSignatureParameters;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Signs with a key the caller holds, in two steps: {@link #dataToSign} returns
 * the bytes the caller's key signs, and {@link #signDocument} builds the signed
 * document around the signature value the caller sends back. The service never
 * holds a key or a PIN.
 *
 * <p>Both steps rebuild the same signature parameters from the same metadata —
 * the signer's certificate chain ({@code certificateChain}, base64 DER, leaf
 * first) and the signing time ({@code signingTime}, epoch milliseconds) among
 * them — so the bytes signed in between are the bytes the document carries.
 * The digest is SHA-256: the caller signs its DigestInfo.
 */
@Service
public class DocumentSigningService {

    private final TrustConfigManager trustConfigManager;

    public DocumentSigningService(TrustConfigManager trustConfigManager) {
        this.trustConfigManager = trustConfigManager;

        // Increase default ASiC/ZIP container limits (anti-zip-bomb protection).
        // Defaults are too restrictive: 1000 files, 1MB threshold, 100x ratio.
        var builder = new SecureContainerHandlerBuilder();
        builder.setMaxAllowedFilesAmount(100_000);
        builder.setThreshold(256_000_000L); // 256 MB decompressed
        builder.setMaxCompressionRatio(1000);
        ZipUtils.getInstance().setZipContainerHandlerBuilder(builder);
    }

    /** The bytes the caller's key signs for this document and metadata. */
    public byte[] dataToSign(byte[] docBytes, String fileName, Map<String, Object> metadata) throws Exception {
        return run(docBytes, fileName, metadata, false);
    }

    /** The signed document, around {@code metadata.signatureValue} (base64). */
    public byte[] signDocument(byte[] docBytes, String fileName, Map<String, Object> metadata) throws Exception {
        return run(docBytes, fileName, metadata, true);
    }

    @SuppressWarnings("unchecked")
    private byte[] run(byte[] docBytes, String fileName, Map<String, Object> metadata, boolean finish)
            throws Exception {
        String format = (String) metadata.get("format");
        String level = (String) metadata.get("level");

        var chain = new ArrayList<CertificateToken>();
        for (Object der : (List<Object>) metadata.get("certificateChain")) {
            chain.add(DSSUtils.loadCertificate(Base64.getDecoder().decode((String) der)));
        }
        if (chain.isEmpty()) {
            throw new IllegalArgumentException("certificateChain is empty");
        }
        var signingTime = new Date(((Number) metadata.get("signingTime")).longValue());

        var doc = new InMemoryDocument(docBytes);
        if (fileName != null && !fileName.isEmpty()) {
            doc.setName(fileName);
        }

        Boolean allowExpired = (Boolean) metadata.getOrDefault("allowExpiredCertificate", false);
        var certVerifier = trustConfigManager.getCertificateVerifier(allowExpired);

        switch (format) {
            case "PAdES" -> {
                var params = new PAdESSignatureParameters();
                params.setSignatureLevel(parseLevel("PAdES", level));
                params.setContentSize(contentSizeForLevel(level));
                configureVisualSignature(params, metadata, docBytes, signingTime);

                var service = new PAdESService(certVerifier);
                configureTSA(service, metadata);
                return step(service, doc, signer(params, chain, signingTime), metadata, finish);
            }
            case "CAdES" -> {
                var params = new CAdESSignatureParameters();
                params.setSignatureLevel(parseLevel("CAdES", level));
                params.setSignaturePackaging(SignaturePackaging.DETACHED);

                var service = new CAdESService(certVerifier);
                configureTSA(service, metadata);
                return step(service, doc, signer(params, chain, signingTime), metadata, finish);
            }
            case "ASiC_E" -> {
                var params = new ASiCWithCAdESSignatureParameters();
                params.aSiC().setContainerType(ASiCContainerType.ASiC_E);
                params.setSignatureLevel(parseLevel("CAdES", level));

                var service = new ASiCWithCAdESService(certVerifier);
                configureTSA(service, metadata);
                return step(service, doc, signer(params, chain, signingTime), metadata, finish);
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

                var service = new XAdESService(certVerifier);
                configureTSA(service, metadata);
                return step(service, doc, signer(params, chain, signingTime), metadata, finish);
            }
            case "JAdES" -> {
                var params = new JAdESSignatureParameters();
                params.setSignatureLevel(parseLevel("JAdES", level));
                params.setSignaturePackaging(SignaturePackaging.DETACHED);
                params.setSigDMechanism(eu.europa.esig.dss.enumerations.SigDMechanism.OBJECT_ID_BY_URI_HASH);

                var service = new JAdESService(certVerifier);
                configureTSA(service, metadata);
                return step(service, doc, signer(params, chain, signingTime), metadata, finish);
            }
            default -> throw new IllegalArgumentException("Unsupported format: " + format);
        }
    }

    private static <SP extends AbstractSignatureParameters<?>> SP signer(SP params, List<CertificateToken> chain,
                                                                        Date signingTime) {
        params.setSigningCertificate(chain.get(0));
        params.setCertificateChain(chain);
        params.bLevel().setSigningDate(signingTime);
        // The caller's key signs a SHA-256 DigestInfo, as the native engine
        // does; DSS would otherwise pick its own default digest.
        params.setDigestAlgorithm(DigestAlgorithm.SHA256);
        return params;
    }

    private static <SP extends AbstractSignatureParameters<?>> byte[] step(DocumentSignatureService<SP, ?> service,
                                                                          DSSDocument doc, SP params,
                                                                          Map<String, Object> metadata,
                                                                          boolean finish) throws Exception {
        if (!finish) {
            return service.getDataToSign(doc, params).getBytes();
        }
        var value = new SignatureValue(params.getSignatureAlgorithm(),
                Base64.getDecoder().decode((String) metadata.get("signatureValue")));
        try (var is = service.signDocument(doc, params, value).openStream()) {
            return is.readAllBytes();
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
                                          byte[] docBytes, Date signingTime) {
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
            // The signing time, not now: both steps must draw the same text.
            sb.append("Date: ").append(java.time.LocalDateTime
                    .ofInstant(signingTime.toInstant(), java.time.ZoneId.systemDefault())
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
