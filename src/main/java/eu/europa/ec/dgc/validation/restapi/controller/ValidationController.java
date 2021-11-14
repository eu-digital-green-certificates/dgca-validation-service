package eu.europa.ec.dgc.validation.restapi.controller;

import eu.europa.ec.dgc.validation.config.DgcConfigProperties;
import eu.europa.ec.dgc.validation.entity.ValidationInquiry;
import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenPayload;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationInitRequest;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationInitResponse;
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
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
@AllArgsConstructor
public class ValidationController {
    private final ValidationService validationService;
    private final ValidationStoreService validationStoreService;
    private final DgcConfigProperties dgcConfigProperties;

    /**
     * init Validation.
     * @param subject subject
     * @param validationInitRequest validationInitRequest
     * @param accessToken accessToken
     * @param version version
     * @return ResponseEntity
     */
    @Operation(
        summary = "validation initialization",
        description = "The validation initialization endpoint delivers to a subject and a public key, "
            + "an initialization\ninformation to indicate to which audience the DCC has to be delivered "
            + "and when this audience\nexpires. Within this lifetime the validation is able to receive "
            + "and validate a DCC for this subject"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "201", description = "Subject created"),
        @ApiResponse(responseCode = "401", description = "Unauthorized."),
        @ApiResponse(responseCode = "400", description = "Bad Request.")})
    @PutMapping(value = "/initialize/{subject}", consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ValidationInitResponse> initValidation(@PathVariable String subject,
                                                                 @Valid @RequestBody ValidationInitRequest
                                                                     validationInitRequest,
                                                                 @RequestHeader("Authorization") String accessToken,
                                                                 @RequestHeader("X-Version") String version,
                                                                 @RequestHeader(value = "X-Crypto-Enc",
                                                                                required = false) Boolean enc,
                                                                 @RequestHeader(value = "X-Crypto-Sig",
                                                                                required = false) Boolean sig) {

        AccessTokenPayload accessTokenPayload = validationService.validateAccessToken(
            dgcConfigProperties.getServiceUrl() + "/initialize/" + subject, subject, accessToken);

        if (accessTokenPayload == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        return new ResponseEntity<ValidationInitResponse>(
            validationService.initValidation(validationInitRequest, subject,enc,sig),
            HttpStatus.CREATED);
    }

    /**
     * check Validation Status.
     * @param subject subject
     * @param accessToken accessToken
     * @param version version
     * @return ResponseEntity
     */
    @Operation(
        summary = "The validation status endpoint provides the validation result of a subject",
        description = "The validation status endpoint provides the validation result of a subject. "
            + "This endpoint is just reachable over a private connection of the service backend"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "OK"),
        @ApiResponse(responseCode = "204", description = "No content, wait for status"),
        @ApiResponse(responseCode = "401", description = "Unauthorized"),
        @ApiResponse(responseCode = "410", description = "Gone. Subject does not exist anymore (TTL expired).")})
    @GetMapping(value = "/status/{subject}", produces = "application/jwt")
    public ResponseEntity<String> checkValidationStatus(@PathVariable String subject,
                                                        @RequestHeader("Authorization") String accessToken,
                                                        @RequestHeader("X-Version") String version) {

        AccessTokenPayload accessTokenPayload = validationService.validateAccessToken(
            dgcConfigProperties.getServiceUrl() + "/status/" + subject, subject, accessToken);

        if (accessTokenPayload == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        ValidationInquiry validationInquiry = validationStoreService.receiveValidation(subject);
        ResponseEntity responseEntity;
        if (validationInquiry == null) {
            responseEntity = ResponseEntity.status(HttpStatus.GONE).build();
        } else if (validationInquiry.getValidationStatus() == ValidationInquiry.ValidationStatus.OPEN) {
            responseEntity = ResponseEntity.status(HttpStatus.NO_CONTENT).build();
        } else {
            return ResponseEntity.ok(validationInquiry.getValidationResult());
        }
        return responseEntity;
    }
}
