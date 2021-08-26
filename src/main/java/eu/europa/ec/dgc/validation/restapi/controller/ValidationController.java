package eu.europa.ec.dgc.validation.restapi.controller;

import eu.europa.ec.dgc.validation.restapi.dto.ValidationInitRequest;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationInitResponse;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationStatusResponse;
import eu.europa.ec.dgc.validation.service.ValidationService;
import io.swagger.v3.oas.annotations.Operation;
import javax.validation.Valid;
import lombok.AllArgsConstructor;
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
    private  final ValidationService validationService;

    @Operation(
            summary = "validation initialization",
            description = "The validation initialization endpoint delivers to a subject and a public key, "
                + "an initialization\ninformation to indicate to which audience the DCC has to be delivered "
                + "and when this audience\nexpires. Within this lifetime the validation is able to receive "
                + "and validate a DCC for this subject"
    )
    @PostMapping(value = "/initialize", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ValidationInitResponse> initValidation(
            @Valid @RequestBody ValidationInitRequest validationInitRequest) {
        return ResponseEntity.ok(validationService.initValidation(validationInitRequest));
    }

    @Operation(
            summary = "The validation status endpoint provides the validation result of a subject",
            description = "The validation status endpoint provides the validation result of a subject. "
                + "This endpoint is just reachable over a private connection of the service backend"
    )
    @GetMapping(value = "/status/{subject}", produces = "application/jwt")
    public ResponseEntity<String> checkValidationStatus(@PathVariable String subject) {
        return ResponseEntity.ok(validationService.checkValidationStatus(subject));
    }
}
