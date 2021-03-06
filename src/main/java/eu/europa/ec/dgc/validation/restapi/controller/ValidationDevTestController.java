package eu.europa.ec.dgc.validation.restapi.controller;

import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenType;
import eu.europa.ec.dgc.validation.restapi.dto.BusinessRuleListItemDto;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationDevRequest;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationStatusResponse;
import eu.europa.ec.dgc.validation.restapi.dto.ValueSetListItemDto;
import eu.europa.ec.dgc.validation.service.BusinessRuleService;
import eu.europa.ec.dgc.validation.service.DccValidator;
import eu.europa.ec.dgc.validation.service.ValueSetService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import java.util.List;
import javax.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
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
    private final BusinessRuleService businessRuleService;
    private final ValueSetService valueSetService;

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


    /**
     * Http Method for getting the business rules list.
     */
    @GetMapping(path = "/devrules", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
        summary = "Gets the a list of all business rule ids country codes and hash values.",
        description = "This method returns a list containing the ids, country codes and hash values of all business "
            + "rules. The hash value can be used to check, if a business rule has changed and needs to be updated. "
            + "The hash value and country code can also be used to download a specific business rule afterwards.",
        tags = {"Business Rules"},
        responses = {
            @ApiResponse(
                responseCode = "200",
                description = "Returns a list of all business rule ids country codes and hash values.",
                content = @Content(
                    mediaType = MediaType.APPLICATION_JSON_VALUE,
                    array = @ArraySchema(schema = @Schema(implementation = BusinessRuleListItemDto.class))))
        }
    )
    public ResponseEntity<List<BusinessRuleListItemDto>> getRules() {
        return ResponseEntity.ok(businessRuleService.getBusinessRulesList());
    }


    /**
     * Http Method for getting the value set list.
     */
    @GetMapping(path = "devvaluesets", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<List<ValueSetListItemDto>> getValueSetList() {
        return ResponseEntity.ok(valueSetService.getValueSetsList());
    }
}
