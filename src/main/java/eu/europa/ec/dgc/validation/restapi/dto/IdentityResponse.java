package eu.europa.ec.dgc.validation.restapi.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import lombok.Data;

@Data
public class IdentityResponse {
    String id;
    List<VerificationMethod> verificationMethod;
}
