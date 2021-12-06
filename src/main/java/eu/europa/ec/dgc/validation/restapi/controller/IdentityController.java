package eu.europa.ec.dgc.validation.restapi.controller;

import eu.europa.ec.dgc.validation.restapi.dto.IdentityResponse;
import eu.europa.ec.dgc.validation.service.IdentityService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import lombok.AllArgsConstructor;
import org.springframework.http.CacheControl;
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

    private static final String PATH_ALL = "/identity";
    private static final String PATH_ELEMENT = "/identity/{element}";
    private static final String PATH_ELEMENT_TYPE = "/identity/{element}/{type}";

    /**
     * get identity document.
     * @param element null or validationMethod
     * @param type null or key type
     * @return identity document
     */
    @Operation(
        summary = "The identity endpoint provides the validation service identity document which contains the used encryption schemas and the associated keys/verification methods.",
        description = "The identity document is downloaded by the wallet apps to encrypt the DCC with the right crypto material."
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "OK")})
    @GetMapping(value = { PATH_ALL, PATH_ELEMENT, PATH_ELEMENT_TYPE }, produces = "application/json")
    public ResponseEntity<IdentityResponse> identity(
            @PathVariable(name = "element", required = false) final String element,
            @PathVariable(name = "type", required = false) final String type) {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noCache())
                .body(identityService.getIdentity(element, type));
    }
}
