package eu.europa.ec.dgc.validation.restapi.controller;

import eu.europa.ec.dgc.validation.entity.ValidationInquiry;
import eu.europa.ec.dgc.validation.restapi.dto.IdentityResponse;
import eu.europa.ec.dgc.validation.service.IdentityService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
@AllArgsConstructor
public class IdentityController {
    private final IdentityService identityService;

    @Operation(
            summary = "The validation status endpoint provides the validation result of a subject",
            description = "The validation status endpoint provides the validation result of a subject. " +
                    "This endpoint is just reachable over a private connection of the service backend"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "OK")})
    @GetMapping(value = "/identity", produces = "application/json")
    public ResponseEntity<IdentityResponse> identity() {
        return ResponseEntity.ok(identityService.getIdentity());
    }
}
