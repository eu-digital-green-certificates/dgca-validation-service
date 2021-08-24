package eu.europa.ec.dgc.validation;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.Test;

class JwtNimbusTest {

    @Test
    void testJwtGen() throws Exception {
        ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
                .keyID("123")
                .generate();
        ECKey ecPublicJWK = ecJWK.toPublicJWK();

        // Create the EC signer
        JWSSigner signer = new ECDSASigner(ecJWK);

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("sub","subject");
        JSONArray jsonArray = new JSONArray();
        jsonArray.appendElement(2);
        jsonArray.appendElement(3);
        jsonObject.put("result",jsonArray);

        // Creates the JWS object with payload
        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(ecJWK.getKeyID()).build(),
                new Payload(jsonObject));

        // Compute the EC signature
        jwsObject.sign(signer);

        // Serialize the JWS to compact form
        String s = jwsObject.serialize();
        System.out.println(s);

    }
}
