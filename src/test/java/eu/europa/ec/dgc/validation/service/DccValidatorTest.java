package eu.europa.ec.dgc.validation.service;

import dgca.verifier.app.decoder.base45.Base45Service;
import dgca.verifier.app.decoder.base45.DefaultBase45Service;
import eu.europa.ec.dgc.utils.CertificateUtils;
import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenConditions;
import eu.europa.ec.dgc.validation.restapi.dto.AccessTokenType;
import eu.europa.ec.dgc.validation.restapi.dto.ValidationStatusResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import org.aspectj.lang.annotation.Before;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

class DccValidatorTest {
    private SignerInformationService signerInformationService;
    private DccValidator dccValidator;

    @BeforeEach
    public void setup() throws Exception {
        signerInformationService = mock(SignerInformationService.class);
        dccValidator = new DccValidator(signerInformationService);
    }

    @Test
    void testDecodeDccWrongPrefix() throws Exception {
        String dcc = "dccwrongprefix";
        List<ValidationStatusResponse.Result> results = dccValidator.validate(dcc, buildConditions(), AccessTokenType.Structure);
        assertEquals(1,results.size());
        assertEquals(ValidationStatusResponse.Result.ResultType.NOK,results.get(0).getResult());
        assertEquals(ValidationStatusResponse.Result.Type.FAILED,results.get(0).getType());
    }

    @Test
    void testDecodeDccWrongBase45() throws Exception {
        String dcc = "HC1:_???";
        List<ValidationStatusResponse.Result> results = dccValidator.validate(dcc, buildConditions(), AccessTokenType.Structure);
        assertEquals(1,results.size());
        assertEquals(ValidationStatusResponse.Result.ResultType.NOK,results.get(0).getResult());
        assertEquals(ValidationStatusResponse.Result.Type.FAILED,results.get(0).getType());
    }

    @Test
    void testDecodeDccWrongBaseCompression() throws Exception {
        String dcc = "HC1:Y69 VD82EEC8NWEO2";
        List<ValidationStatusResponse.Result> results = dccValidator.validate(dcc, buildConditions(), AccessTokenType.Structure);
        assertEquals(1,results.size());
        assertEquals(ValidationStatusResponse.Result.ResultType.NOK,results.get(0).getResult());
        assertEquals(ValidationStatusResponse.Result.Type.FAILED,results.get(0).getType());
    }

    @Test
    void testDecodeDccWrongCBor() throws Exception {
        String dcc = "HC1:NCF0YU0+PIKP68E%E52V5N0065LV0";
        List<ValidationStatusResponse.Result> results = dccValidator.validate(dcc, buildConditions(), AccessTokenType.Structure);
        assertEquals(1,results.size());
        assertEquals(ValidationStatusResponse.Result.ResultType.NOK,results.get(0).getResult());
        assertEquals(ValidationStatusResponse.Result.Type.FAILED,results.get(0).getType());
    }

    @Test
    void testDecodeDccCborButNotCose() throws Exception {
        String dcc = "HC1:NCFEZP699.MPJ2BBQ5B95HB05S3$P0";
        List<ValidationStatusResponse.Result> results = dccValidator.validate(dcc, buildConditions(), AccessTokenType.Structure);
        assertEquals(1,results.size());
        assertEquals(ValidationStatusResponse.Result.ResultType.NOK,results.get(0).getResult());
        assertEquals(ValidationStatusResponse.Result.Type.FAILED,results.get(0).getType());
    }

    @Test
    void testDecodeDccWrongSchema() throws Exception {
        String dcc = "HC1:NCFOXN%TS3DH.UK+QAKVUY*N9 1 *MMB2.7JJ598RT7.7M*4UEL76SAD6K0P NI4EFSYS:%OD3P9B9LGFIE9MIHJ6" +
                "W48UK.GA68-8DXFDZTAKBI/8D:8DOVD7KDP9CZXI$MI1VCSWC%PDMOL+9DJZIR9KVR3JZI+EB42KE2K CDQ.CH/SJHDPKS7BC-E" +
                "U6%TIYDDT36Z3GWT-O30VSLY2JFTH8CR9C:XIBEIVG395EV3EVCK09DT9C.XIM$JK7JCIIFVA.QO5VA81K0ECM8CXVDC8C 1JI" +
                "7J+TN:VL/35D266W5HW62Z4/Z7$35AL6JINQ+MN/Q19QE8Q4A7E:7LYP3PQCFT442/BE IQGSNG%PY8W YPB2N2.6P5CR 5YO" +
                "M0WP2YO.V9S8HQM5UF20OLC$D66KV8V7.R3ET/JH.%K2TLFPJ05E5DFYYR7RTS1U3Z4ZYNWKIX10A1VC4";
        List<ValidationStatusResponse.Result> results = dccValidator.validate(dcc, buildConditions(), AccessTokenType.Structure);
        assertEquals(1,results.size());
        assertEquals(ValidationStatusResponse.Result.ResultType.NOK,results.get(0).getResult());
        assertEquals(ValidationStatusResponse.Result.Type.FAILED,results.get(0).getType());
    }

    @Test
    void testDecodeDccStructureOK() throws Exception {
        String dcc = "HC1:6BFOXN%TSMAHN-H/P8JU6+BS.5E9%UD82.7JJ59W2TT+FM*4/IQ0YVKQCPTHCV4*XUA2PWKP/HLIJL8JF8J" +
                "F7LPMIH-O92UQ7QQ%NH0LA5O6/UIGSU7QQ7NGWWBA 7.UIAYU3X3SH90THYZQ H9+W3.G8MSGPRAAUICO1DV59UE6Q1M650 LHZA0" +
                "D9E2LBHHGKLO-K%FGLIA5D8MJKQJK JMDJL9GG.IA.C8KRDL4O54O4IGUJKJGI.IAHLCV5GVWN.FKP123NJ%HBX/KR968X2-36/-K" +
                "KTCY73$80PU6QW6H+932QDONAC5287T:7N95*K64POPGI*%DC*G2KV SU1Y6B.QEN7+SQ4:4P2C:8UFOFC072.T2PE0*J65UY.2ED" +
                "TYJDK8W$WKF.VUV9L+VF3TY71NSFIM2F:47*J0JLV50M1WB*C";
        List<ValidationStatusResponse.Result> results = dccValidator.validate(dcc, buildConditions(), AccessTokenType.Structure);
        assertEquals(1,results.size());
        assertEquals(ValidationStatusResponse.Result.ResultType.OK,results.get(0).getResult());
        assertEquals(ValidationStatusResponse.Result.Type.PASSED,results.get(0).getType());
    }

    @Test
    void testDecodeDccCrypto() throws Exception {
        mockDccCerts();
        String dcc = "HC1:NCF970%90T9WTWGVLK879%EHLE7A1KW8HX*4.AB3XK3F3D86*743F3ZU5.FK1JC X8Y50.FK6ZK7:EDOLFVC*70B$D%" +
                " D3IA4W5646646/96OA76KCN9E%961A69L6QW6B46XJCCWENF6OF63W5NW6-96WJCT3E6N8WJC0FD4:473DSDDF+AKG7RCBA69" +
                "C6A41AZM8JNA5N8LN9VY91OASTA.H9MB8I6A946.JCP9EJY8L/5M/5546.96D46%JCKQE:+9 8D3KC.SC4KCD3DX47B46IL6646" +
                "I*6..DX%DLPCG/D$2DMIALY8/B9ZJC3/DIUADLFE4F-PDI3D7WERB8YTAUIAI3D1 C5LE6%E$PC5$CUZCY$5Y$5JPCT3E5JDOA7" +
                "3467463W5WA6:68 GTFHDZUTOZLO2FL7OU9AQUOAR0NXHY78%$8L65Q93Z81AA60$DUF6XF4EJVUXG4UTN*2YG51UM/.2PGO8P" +
                "I*GS8%LXKBJW8:G6O5";
        List<ValidationStatusResponse.Result> results = dccValidator.validate(dcc, buildConditions(), AccessTokenType.Cryptographic);
        for (ValidationStatusResponse.Result result : results) {
            assertEquals(ValidationStatusResponse.Result.ResultType.OK,result.getResult());
            assertEquals(ValidationStatusResponse.Result.Type.PASSED,result.getType());
        }
        assertEquals(ValidationStatusResponse.Result.ResultType.OK,results.get(0).getResult());
        assertEquals(ValidationStatusResponse.Result.Type.PASSED,results.get(0).getType());
    }

    private void mockDccCerts() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");

        File keyFile = new File("src/test/resources/dcc-sign-test.jks");
        assertTrue(keyFile.isFile());
        String keyName = "edgc_dev_ec";
        try (InputStream is = new FileInputStream(keyFile)) {
            final char[] privateKeyPassword = "dgca".toCharArray();
            keyStore.load(is, privateKeyPassword);
            KeyStore.PasswordProtection keyPassword =
                    new KeyStore.PasswordProtection("dgca".toCharArray());

            KeyStore.PrivateKeyEntry privateKeyEntry =
                    (KeyStore.PrivateKeyEntry) keyStore.getEntry(keyName, keyPassword);
            Certificate cert = keyStore.getCertificate(keyName);
            List<Certificate> certs = Collections.singletonList(cert);
            CertificateUtils certificateUtils = new CertificateUtils();
            String kidBase64 = certificateUtils.getCertKid((X509Certificate) cert);
            doReturn(certs).when(signerInformationService).getCertificates(anyString());
        }
    }

    private AccessTokenConditions buildConditions() {
        AccessTokenConditions accessTokenConditions = new AccessTokenConditions();
        accessTokenConditions.setHash("hash");
        accessTokenConditions.setLang("en-en");
        accessTokenConditions.setFnt("TRZEWIK");
        accessTokenConditions.setGnt("ARTUR");
        accessTokenConditions.setDob("1990-01-01");
        accessTokenConditions.setCoa("NL");
        accessTokenConditions.setCod("DE");
        accessTokenConditions.setRoa("AW");
        accessTokenConditions.setRod("BW");
        accessTokenConditions.setType(new String[] {"v","t"});
        accessTokenConditions.setValidationClock("2021-01-29T12:00:00+01:00");
        accessTokenConditions.setValidFrom("2021-01-29T12:00:00+01:00");
        accessTokenConditions.setValidTo("2021-01-30T12:00:00+01:00");
        return accessTokenConditions;
    }
}