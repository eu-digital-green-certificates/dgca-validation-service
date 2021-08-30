package eu.europa.ec.dgc.validation.restapi.controller;

import eu.europa.ec.dgc.validation.entity.ValidationInquiry;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationInitRequest;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationInitResponse;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationStatusResponse;
import eu.europa.ec.dgc.validation.service.ValidationService;
import eu.europa.ec.dgc.validation.service.ValidationStoreService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import javax.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
@AllArgsConstructor
public class ValidationController {
    private final ValidationService validationService;
    private final ValidationStoreService validationStoreService;

    @Operation(
            summary = "validation initialization",
            description = "The validation initialization endpoint delivers to a subject and a public key, "
                + "an initialization\ninformation to indicate to which audience the DCC has to be delivered "
                + "and when this audience\nexpires. Within this lifetime the validation is able to receive "
                + "and validate a DCC for this subject"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "signature created"),
            @ApiResponse(responseCode = "401", description = "Unauthorized, if no client certificate was matched"),
            @ApiResponse(responseCode = "400", description = "Response Body with Error Details.")})
    @PostMapping(value = "/initialize", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ValidationInitResponse> initValidation(
            @Valid @RequestBody ValidationInitRequest validationInitRequest) {
        return ResponseEntity.ok(validationService.initValidation(validationInitRequest));
    }

    @Operation(
            summary = "The validation status endpoint provides the validation result of a subject",
            description = "The validation status endpoint provides the validation result of a subject. "
                + "This endpoint is just reachable over a private connection of the service backend"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "OK"),
            @ApiResponse(responseCode = "204", description = "No content, wait for status"),
            @ApiResponse(responseCode = "401", description = "Unauthorized, if no client certificate was matched"),
            @ApiResponse(responseCode = "410", description = "Gone. Subject does not exist anymore (TTL expired).")})
    @GetMapping(value = "/status/{subject}", produces = "application/jwt")
    public ResponseEntity<String> checkValidationStatus(@PathVariable String subject) {
        ValidationInquiry validationInquiry = validationStoreService.receiveValidation(subject);
        ResponseEntity responseEntity;
        if (validationInquiry==null) {
            responseEntity = ResponseEntity.status(HttpStatus.GONE).build();
        } else if (validationInquiry.getValidationStatus()== ValidationInquiry.ValidationStatus.OPEN) {
            responseEntity = ResponseEntity.status(HttpStatus.NO_CONTENT).build();
        } else {
            return ResponseEntity.ok(validationInquiry.getValidationResult());
        }
        return responseEntity;

    }
}
