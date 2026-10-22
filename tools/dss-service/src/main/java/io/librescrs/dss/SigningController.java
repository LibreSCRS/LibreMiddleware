// SPDX-License-Identifier: LGPL-2.1-or-later
package io.librescrs.dss;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.multipart.FilePart;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.Map;

@RestController
public class SigningController {

    private final DocumentSigningService documentSigningService;
    private final TrustConfigManager trustConfigManager;
    // Strict Jackson configuration: reject unknown fields, null-for-primitive,
    // and numeric-for-enum coercions so that malformed or attacker-injected
    // payloads fail fast instead of silently falling through.
    private final ObjectMapper objectMapper = JsonMapper.builder()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)
            .configure(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES, true)
            .configure(DeserializationFeature.FAIL_ON_NUMBERS_FOR_ENUMS, true)
            .build();

    public SigningController(DocumentSigningService documentSigningService,
                             TrustConfigManager trustConfigManager) {
        this.documentSigningService = documentSigningService;
        this.trustConfigManager = trustConfigManager;
    }

    private static String sanitizeErrorMessage(Exception e) {
        String message = e.getMessage();
        if (message == null || message.isEmpty()) {
            message = "Internal signing error";
        }
        return message;
    }

    @GetMapping("/health")
    public Map<String, Object> health() {
        return Map.of("status", "ok",
                       "version", "1.0.0",
                       "trustConfigured", trustConfigManager.isConfigured());
    }

    @PostMapping("/config")
    public ResponseEntity<?> configure(@RequestBody Map<String, Object> config) {
        try {
            trustConfigManager.configure(config);
            return ResponseEntity.ok(Map.of("status", "ok"));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body(Map.of("error", sanitizeErrorMessage(e)));
        }
    }

    /** Step one: the bytes the caller's key signs (application/octet-stream). */
    @PostMapping(value = "/sign/data-to-sign", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public Mono<ResponseEntity<?>> dataToSign(@RequestPart("document") FilePart document,
                                               @RequestPart("metadata") String metadataJson) {
        return signingStep(document, metadataJson, documentSigningService::dataToSign);
    }

    /** Step two: the signed document around the caller's signature value. */
    @PostMapping(value = "/sign/document", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public Mono<ResponseEntity<?>> signDocument(@RequestPart("document") FilePart document,
                                                 @RequestPart("metadata") String metadataJson) {
        return signingStep(document, metadataJson, documentSigningService::signDocument);
    }

    @FunctionalInterface
    private interface Step {
        byte[] apply(byte[] docBytes, String fileName, Map<String, Object> metadata) throws Exception;
    }

    @SuppressWarnings("unchecked")
    private Mono<ResponseEntity<?>> signingStep(FilePart document, String metadataJson, Step step) {
        return DataBufferUtils.join(document.content())
                .map(dataBuffer -> {
                    byte[] docBytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(docBytes);
                    DataBufferUtils.release(dataBuffer);
                    return docBytes;
                })
                .map(docBytes -> {
                    try {
                        Map<String, Object> metadata = objectMapper.readValue(metadataJson, Map.class);
                        byte[] result = step.apply(docBytes, document.filename(), metadata);
                        return (ResponseEntity<?>) ResponseEntity.ok()
                                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                                .body(result);
                    } catch (Exception e) {
                        return (ResponseEntity<?>) ResponseEntity.internalServerError()
                                .body(Map.of("error", sanitizeErrorMessage(e)));
                    }
                });
    }
}
