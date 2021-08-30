package eu.europa.ec.dgc.validation;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import java.security.interfaces.ECPrivateKey;
import java.util.Arrays;
import java.util.Date;
import java.util.UUID;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi;
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

    @Test
    void testJwtEncryption() throws Exception {
        ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
                .keyID("123")
                .generate();
        ECKey ecPublicJWK = ecJWK.toPublicJWK();

        JWEEncrypter encrypter = new ECDHEncrypter(ecPublicJWK);

        Date now = new Date();

        JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                .issuer("https://openid.net")
                .subject("alice")
                .audience(Arrays.asList("https://app-one.com", "https://app-two.com"))
                .expirationTime(new Date(now.getTime() + 1000*60*10)) // expires in 10 minutes
                .notBeforeTime(now)
                .issueTime(now)
                .jwtID(UUID.randomUUID().toString())
                .build();

        System.out.println(jwtClaims.toJSONObject());

        // Request JWT encrypted with RSA-OAEP-256 and 128-bit AES/GCM
        JWEHeader header = new JWEHeader(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256GCM);

        // Create the encrypted JWT object
        EncryptedJWT jwt = new EncryptedJWT(header, jwtClaims);

        // Do the actual encryption
        jwt.encrypt(encrypter);

        // Serialise to JWT compact form
        String jwtString = jwt.serialize();

        System.out.println(jwtString);

        EncryptedJWT jwtDeparsed = EncryptedJWT.parse(jwtString);

        // Create a decrypter with the specified private RSA key
        ECDHDecrypter decrypter = new ECDHDecrypter((ECPrivateKey) ecJWK.toPrivateKey());

        // Decrypt
        jwtDeparsed.decrypt(decrypter);

        System.out.println(jwtDeparsed.getJWTClaimsSet());

        System.out.println(jwtDeparsed.getJWTClaimsSet().getIssuer());;
        System.out.println(jwtDeparsed.getJWTClaimsSet().getSubject());
        System.out.println(jwtDeparsed.getJWTClaimsSet().getAudience().size());
        System.out.println(jwtDeparsed.getJWTClaimsSet().getExpirationTime());
        System.out.println(jwtDeparsed.getJWTClaimsSet().getNotBeforeTime());
        System.out.println(jwtDeparsed.getJWTClaimsSet().getIssueTime());
        System.out.println(jwtDeparsed.getJWTClaimsSet().getJWTID());

    }

}
