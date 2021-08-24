package eu.europa.ec.dgc.validation.restapi.dto;

import java.util.List;
import lombok.Data;

@Data
public class IdentityResponse {
    String Id;
    List<VerificationMethod> verificationMethod;
}
