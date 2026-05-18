// SPDX-License-Identifier: LGPL-2.1-or-later
package io.librescrs.dss;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import eu.europa.esig.dss.asic.cades.validation.ASiCContainerWithCAdESValidatorFactory;
import eu.europa.esig.dss.asic.xades.validation.ASiCContainerWithXAdESValidatorFactory;
import eu.europa.esig.dss.cades.validation.CMSDocumentValidatorFactory;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.jades.validation.JAdESDocumentValidatorFactory;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidatorFactory;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.DocumentValidatorFactory;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidatorFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.multipart.FilePart;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Local DSS-backed validation oracle for the LibreSCRS signing test
 * suite. Accepts a signed document (any of PAdES / CAdES / XAdES /
 * JAdES / ASiC-E) over multipart, runs it through
 * {@link SignedDocumentValidator#fromDocument(DSSDocument)}, and
 * returns a per-signature JSON summary that matches the C++
 * {@code ValidationResult} struct one-to-one.
 *
 * <p>All five ETSI {@link DocumentValidatorFactory} implementations
 * are touched at class-load time so that even if Spring Boot's
 * nested-jar SPI loader misses one for any reason, the factory class
 * is reachable.</p>
 */
@RestController
public class ValidationService {

    private static final Logger log = LoggerFactory.getLogger(ValidationService.class);

    // Touch every factory we expect to be on the classpath so that any
    // misconfiguration (missing dependency, shaded jar dropping SPI
    // entries, etc.) fails loudly at class-load instead of silently
    // returning "Document format not recognized" later.
    static {
        @SuppressWarnings("unused")
        Class<?>[] factories = new Class<?>[] {
                PDFDocumentValidatorFactory.class,
                CMSDocumentValidatorFactory.class,
                XMLDocumentValidatorFactory.class,
                JAdESDocumentValidatorFactory.class,
                ASiCContainerWithCAdESValidatorFactory.class,
                ASiCContainerWithXAdESValidatorFactory.class,
        };
    }

    // DSS 6.4 ships the default constraint.xml inside dss-policy-jaxb. The
    // no-arg validateDocument() overload relies on a classpath scan that
    // silently fails inside the Spring Boot fat-jar; load the policy
    // ourselves once and reuse the parsed instance across every request.
    private static volatile ValidationPolicy cachedPolicy;

    private static ValidationPolicy loadPolicy() throws Exception {
        ValidationPolicy local = cachedPolicy;
        if (local == null) {
            synchronized (ValidationService.class) {
                local = cachedPolicy;
                if (local == null) {
                    try (InputStream stream = ValidationPolicyFacade.class
                            .getResourceAsStream("/policy/constraint.xml")) {
                        if (stream == null) {
                            throw new IllegalStateException(
                                    "/policy/constraint.xml not on classpath; "
                                            + "is dss-policy-jaxb missing?");
                        }
                        local = ValidationPolicyFacade.newFacade()
                                .getValidationPolicy(stream);
                        cachedPolicy = local;
                    }
                }
            }
        }
        return local;
    }

    private final TrustConfigManager trustConfigManager;

    private final ObjectMapper objectMapper = JsonMapper.builder()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .build();

    public ValidationService(TrustConfigManager trustConfigManager) {
        this.trustConfigManager = trustConfigManager;
    }

    @PostMapping(value = "/validate", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public Mono<ResponseEntity<?>> validate(@RequestPart("document") FilePart document,
                                             @RequestPart("metadata") String metadataJson,
                                             @RequestPart(name = "originalDocument", required = false)
                                                     FilePart originalDocument) {
        Mono<byte[]> docMono = readPart(document);
        Mono<byte[]> originalMono = originalDocument != null
                ? readPart(originalDocument)
                : Mono.just(new byte[0]);

        return Mono.zip(docMono, originalMono).map(tuple -> {
            byte[] signedBytes = tuple.getT1();
            byte[] originalBytes = tuple.getT2();
            try {
                Map<String, Object> metadata = parseMetadata(metadataJson);
                String packaging = stringOrEmpty(metadata.get("packaging"));

                Map<String, Object> body = runValidation(signedBytes, originalBytes, packaging);
                return (ResponseEntity<?>) ResponseEntity.ok(body);
            } catch (IllegalArgumentException e) {
                log.warn("Validation request rejected: {}", e.getMessage());
                return (ResponseEntity<?>) ResponseEntity.badRequest()
                        .body(errorBody(e.getMessage()));
            } catch (Exception e) {
                log.error("Validation oracle internal error", e);
                return (ResponseEntity<?>) ResponseEntity.internalServerError()
                        .body(errorBody(safeMessage(e)));
            }
        });
    }

    private Map<String, Object> runValidation(byte[] signedBytes, byte[] originalBytes, String packaging) {
        DSSDocument signedDoc = new InMemoryDocument(signedBytes, "signed");

        SignedDocumentValidator validator;
        try {
            validator = SignedDocumentValidator.fromDocument(signedDoc);
        } catch (Exception e) {
            return failureBody("Document format not recognized: " + safeMessage(e));
        }

        validator.setCertificateVerifier(trustConfigManager.getCertificateVerifier(true));

        if ("DETACHED".equalsIgnoreCase(packaging)) {
            if (originalBytes == null || originalBytes.length == 0) {
                return failureBody("DETACHED packaging requires originalDocument");
            }
            validator.setDetachedContents(List.of(new InMemoryDocument(originalBytes, "original")));
        }

        ValidationPolicy policy;
        try {
            policy = loadPolicy();
        } catch (Exception e) {
            return failureBody("Unable to load DSS validation policy: " + safeMessage(e));
        }

        Reports reports = validator.validateDocument(policy);
        return summarise(reports);
    }

    private static Map<String, Object> summarise(Reports reports) {
        SimpleReport simple = reports.getSimpleReport();
        List<String> sigIds = simple.getSignatureIdList();

        List<Map<String, Object>> signatures = new ArrayList<>();
        List<String> indications = new ArrayList<>();
        boolean allValid = !sigIds.isEmpty();

        for (int i = 0; i < sigIds.size(); i++) {
            String id = sigIds.get(i);
            Indication ind = simple.getIndication(id);
            SubIndication sub = simple.getSubIndication(id);
            SignatureLevel level = simple.getSignatureFormat(id);

            String indStr = ind != null ? ind.name() : "";
            String subStr = sub != null ? sub.name() : "";
            String levelStr = level != null ? level.name() : "";

            boolean sigValid = ind == Indication.TOTAL_PASSED;
            if (!sigValid) {
                allValid = false;
            }

            indications.add(levelStr);

            Map<String, Object> sigInfo = new LinkedHashMap<>();
            sigInfo.put("index", i);
            sigInfo.put("level", levelStr);
            sigInfo.put("valid", sigValid);
            sigInfo.put("indication", indStr);
            sigInfo.put("subIndication", subStr);
            sigInfo.put("errors", messagesToStrings(simple.getAdESValidationErrors(id)));
            sigInfo.put("warnings", messagesToStrings(simple.getAdESValidationWarnings(id)));
            signatures.add(sigInfo);
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("valid", allValid);
        body.put("signatureCount", sigIds.size());
        body.put("signatures", signatures);
        body.put("indications", indications);
        body.put("error", "");
        return body;
    }

    private static List<String> messagesToStrings(List<Message> messages) {
        if (messages == null || messages.isEmpty()) {
            return List.of();
        }
        List<String> out = new ArrayList<>(messages.size());
        for (Message m : messages) {
            String txt = m.getValue();
            if (txt == null) {
                txt = m.getKey() != null ? m.getKey() : "";
            }
            out.add(txt);
        }
        return out;
    }

    private static Map<String, Object> failureBody(String error) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", false);
        body.put("valid", false);
        body.put("signatureCount", 0);
        body.put("signatures", List.of());
        body.put("indications", List.of());
        body.put("error", error);
        return body;
    }

    private static Map<String, Object> errorBody(String message) {
        Map<String, Object> body = new HashMap<>();
        body.put("success", false);
        body.put("valid", false);
        body.put("error", message);
        return body;
    }

    private Map<String, Object> parseMetadata(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> parsed = objectMapper.readValue(json, Map.class);
            return parsed != null ? parsed : Map.of();
        } catch (Exception e) {
            throw new IllegalArgumentException("Malformed metadata JSON: " + safeMessage(e), e);
        }
    }

    private static String stringOrEmpty(Object o) {
        return o == null ? "" : o.toString().toUpperCase(Locale.ROOT);
    }

    private static String safeMessage(Throwable t) {
        String m = t.getMessage();
        return (m == null || m.isBlank()) ? t.getClass().getSimpleName() : m;
    }

    private static Mono<byte[]> readPart(FilePart part) {
        return DataBufferUtils.join(part.content()).map(buf -> {
            byte[] bytes = new byte[buf.readableByteCount()];
            buf.read(bytes);
            DataBufferUtils.release(buf);
            return bytes;
        });
    }
}
