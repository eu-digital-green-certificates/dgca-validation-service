package eu.europa.ec.dgc.validation.restapi.controller;


import eu.europa.ec.dgc.validation.restapi.dto.DccValidationRequest;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationInitRequest;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationInitResponse;
import eu.europa.ec.dgc.validation.service.ValidationService;
import io.swagger.v3.oas.annotations.Operation;
import javax.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
@AllArgsConstructor
public class DCCProvisioningController {
    private  final ValidationService validationService;

    @Operation(
            summary = "The provision endpoint is the public endpoint where DCCs can be provided for a subject. The\n" +
                    "endpoint receives the encrypted DCC, validates it and creates the result for the subject.",
            description = "The provision endpoint is the public endpoint where DCCs can be provided for a subject. The\n" +
                    "endpoint receives the encrypted DCC, validates it and creates the result for the subject."
    )
    @PostMapping(value = "/validate", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> initValidation(
            @Valid @RequestBody DccValidationRequest dccValidationRequest,
            @RequestHeader("Authorization") String accessToken) {
        return ResponseEntity.ok(validationService.validate(dccValidationRequest, accessToken));
    }
}
