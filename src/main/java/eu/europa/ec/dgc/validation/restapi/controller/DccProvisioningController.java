package eu.europa.ec.dgc.validation.restapi.controller;


import eu.europa.ec.dgc.validation.restapi.dto.DccValidationRequest;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationInitRequest;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationInitResponse;
import eu.europa.ec.dgc.validation.service.ValidationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import javax.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
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
public class DccProvisioningController {
    private  final ValidationService validationService;
    private static final String TOKEN_PREFIX = "Bearer ";

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
            @ApiResponse(responseCode = "422", description = "Unprocessable Entity. Wrong Signature of the Subject," +
                    " Wrong Encryption or any other problem with the encoding")})
    @PostMapping(value = "/validate", consumes = MediaType.APPLICATION_JSON_VALUE, produces = "application/jwt")
    public ResponseEntity<String> initValidation(
            @Valid @RequestBody DccValidationRequest dccValidationRequest,
            @RequestHeader("Authorization") String accessToken) {
        ResponseEntity<String> result;
        if (accessToken!=null && accessToken.startsWith(TOKEN_PREFIX)) {
            String resultToken = validationService.validate(dccValidationRequest, accessToken.substring(TOKEN_PREFIX.length()));
            if (resultToken != null) {
                result = ResponseEntity.ok(resultToken);
            } else {
                result = ResponseEntity.status(HttpStatus.GONE).build();
            }
        } else {
            result = ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        return result;
    }
}
