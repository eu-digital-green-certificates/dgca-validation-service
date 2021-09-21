package eu.europa.ec.dgc.validation.restapi.controller;

import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenType;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationDevRequest;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationStatusResponse;
import eu.europa.ec.dgc.validation.service.DccValidator;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import java.util.List;
import javax.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
@AllArgsConstructor
@Profile("devvalidate")
public class ValidationDevTestController {
    private final DccValidator dccValidator;

    /**
     * dev Validate.
     * @param validationDevRequest validationDevRequest
     * @return ResponseEntity
     */
    @Operation(
        summary = "The provision endpoint is the public endpoint where DCCs can be provided for a subject. The "
            + "endpoint receives the encrypted DCC, validates it and creates the result for the subject.",
        description = "The provision endpoint is the public endpoint where DCCs can be provided for a subject. The "
            + "endpoint receives the encrypted DCC, validates it and creates the result for the subject."
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "OK"),
        @ApiResponse(responseCode = "401", description = "Unauthorized, if no access token are provided"),
        @ApiResponse(responseCode = "400", description = "Bad Request, content of the provide data is malformed"),
        @ApiResponse(responseCode = "410", description = "Gone, Subject does not exists any more"),
        @ApiResponse(responseCode = "422", description = "Unprocessable Entity. Wrong Signature of the Subject,"
            + " Wrong Encryption or any other problem with the encoding")})
    @PostMapping(value = "/devvalidate", consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<List<ValidationStatusResponse.Result>> devValidate(
        @Valid @RequestBody ValidationDevRequest validationDevRequest) {
        return ResponseEntity.ok(dccValidator.validate(validationDevRequest.getDcc(),
            validationDevRequest.getAccessTokenPayload().getConditions(),
            AccessTokenType.getTokenForInt(validationDevRequest.getAccessTokenPayload().getType()), false));
    }
}
