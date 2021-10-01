package eu.europa.ec.dgc.validation;

import com.nimbusds.jose.util.X509CertUtils;
import eu.europa.ec.dgc.utils.CertificateUtils;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class CertTest {
    @Test
    void checkCert() throws Exception {
        String cert1 = "MIIBozCCAUmgAwIBAgIUEGv/tz78KWn+b1PchLILG8gruEswCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcVmFsaWRhdGlvb" +
            "kRlY29yYXRvclNpZ25LZXktMTAeFw0yMTA5MTYwOTExNTVaFw0yMTEwMTYwOTExNTVaMCcxJTAjBgNVBAMMHFZhbGlkYXRpb25EZWNv" +
            "cmF0b3JTaWduS2V5LTEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQg+u1ixb34m7Cn+a3uHwUncuAVEhSXZWWZyXUNSbmA0eXQucc" +
            "gvgl9/qaDrJWF6F1CIy+SFS1O+YUhRY41IkSfo1MwUTAdBgNVHQ4EFgQUAITPash2Jqh2hyl92dk6hM19iygwHwYDVR0jBBgwFoAUAI" +
            "TPash2Jqh2hyl92dk6hM19iygwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEAi9/ZywRGVKfk9daJDPDxzUGzQHHhL" +
            "CwURRMxnW+un1gCIEvRaDWOttYJuJJAWZDYg9wQmuFQzG/OyVJiXxOMoFFe";
        String cert2 = "MIIJvjCCCKagAwIBAgIQAYbW6QQnQfVNplcmMR5VeDANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJVUzEVMBMGA1UEC" +
            "hMMRGlnaUNlcnQgSW5jMSkwJwYDVQQDEyBEaWdpQ2VydCBUTFMgUlNBIFNIQTI1NiAyMDIwIENBMTAeFw0yMTAzMTkwMDAwMDBaFw0y" +
            "MjAzMjQyMzU5NTlaMHQxCzAJBgNVBAYTAkRFMRswGQYDVQQIDBJCYWRlbi1Xw7xydHRlbWJlcmcxETAPBgNVBAcTCFdhbGxkb3JmMQ8" +
            "wDQYDVQQKEwZTQVAgU0UxJDAiBgNVBAMMGyouY2YuZXUxMC5oYW5hLm9uZGVtYW5kLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADC" +
            "CAgoCggIBAMJ5Mcr58LEpbVqhlDhgMTYvKBLLGJfN9CQpJ4HRqVOy0mRHZTPKsJcm6VgAbMFqpPkBooBjn281+0iTqh3oK7+QzkmjywC" +
            "p4Qyv5yhYb2Ko+Pfv2OtB32mkZaI6WZNU2DMaF5nvqZECBOvCePzVJr0C4VIe/LmFxgG6zIeZIKqCDTvwJFWcNMIrnKS9hHGrCoxbxlA" +
            "a7iQTgor2+i/giAhfufc6UJmLptYkFtscbdXi0wa6yifIw5S8O+c3VLsV1oQwRrBv4taJahpClgktHqgCUDStI69EDKBz2jpfNq3Em5" +
            "Yq4fUEu1iLP9WsuvQV751gFknBN+vc3b8reGpj+8nG8RHeaqkf/n4KQeeFnKEqKlbXcmadBGRu9o84d2yq9EZTNIRy7q5A0FcSMvenw" +
            "E7qeSQuW7zzYUC5J+vVSSKLYHNdHq8dv4H6ycyAkKKa/4EXt7/F2UjZlatSgvZd+zZc5CwGj/SMk8xdhW7G8BIFcNkQ7wW+8KaVTg+5f" +
            "oWdP1uicWnkaBn4mH4TSUW8cO3U7K/bXC0ZbdztJw/CsaOE3haRYp5lVy6Y1eiqGqSfhqFuJ1Xat1pMb4eq53oVs/ioKUug5Xu0+tIE" +
            "QHYlvskmhh1PxJBsQZlTUtzA8jSjrzUyp42iiS1RIw5s7UT7t2mmZ8rzDZGFLXhakSZOfjtDAgMBAAGjggVvMIIFazAfBgNVHSMEGDA" +
            "WgBS3a6LqqKqEjHnqtNoPmLLFlXa59DAdBgNVHQ4EFgQUd74pqdURkHafSLfNsG94ISft6GYwggKWBgNVHREEggKNMIICiYIbKi5jZi" +
            "5ldTEwLmhhbmEub25kZW1hbmQuY29tgh8qLnVhYS5jZi5ldTEwLmhhbmEub25kZW1hbmQuY29tgiEqLmxvZ2luLmNmLmV1MTAuaGFuY" +
            "S5vbmRlbWFuZC5jb22CIHhzdWFhLWFwaS5ldTEwLmhhbmEub25kZW1hbmQuY29tgiIqLnhzdWFhLWFwaS5ldTEwLmhhbmEub25kZW1" +
            "hbmQuY29tgiVhdXRoZW50aWNhdGlvbi5ldTEwLmhhbmEub25kZW1hbmQuY29tgicqLmF1dGhlbnRpY2F0aW9uLmV1MTAuaGFuYS5v" +
            "bmRlbWFuZC5jb22CHyouY2ZhcHBzLmV1MTAuaGFuYS5vbmRlbWFuZC5jb22CQSouc3Vic2NyaXB0aW9uLW1hbmFnZW1lbnQtZGFzaG" +
            "JvYXJkLmNmYXBwcy5ldTEwLmhhbmEub25kZW1hbmQuY29tgjEqLm9wZXJhdGlvbnNjb25zb2xlLmNmYXBwcy5ldTEwLmhhbmEub25kZ" +
            "W1hbmQuY29tgigqLmludGVybmFsLmNmYXBwcy5ldTEwLmhhbmEub25kZW1hbmQuY29tgi8qLmF1ZGl0bG9nLXZpZXdlci5jZmFwcHM" +
            "uZXUxMC5oYW5hLm9uZGVtYW5kLmNvbYIkKi5jZXJ0LmNmYXBwcy5ldTEwLmhhbmEub25kZW1hbmQuY29tgh5jb2NrcGl0LmV1MTAua" +
            "GFuYS5vbmRlbWFuZC5jb22CKmF1dGhlbnRpY2F0aW9uLmNlcnQuZXUxMC5oYW5hLm9uZGVtYW5kLmNvbYIsKi5hdXRoZW50aWNhdGl" +
            "vbi5jZXJ0LmV1MTAuaGFuYS5vbmRlbWFuZC5jb20wDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAj" +
            "CBiwYDVR0fBIGDMIGAMD6gPKA6hjhodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUTFNSU0FTSEEyNTYyMDIwQ0ExLmNyb" +
            "DA+oDygOoY4aHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VExTUlNBU0hBMjU2MjAyMENBMS5jcmwwPgYDVR0gBDcwNTA" +
            "zBgZngQwBAgIwKTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ1BTMH0GCCsGAQUFBwEBBHEwbzAkBggrBgEFB" +
            "QcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEcGCCsGAQUFBzAChjtodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaU" +
            "NlcnRUTFNSU0FTSEEyNTYyMDIwQ0ExLmNydDAMBgNVHRMBAf8EAjAAMIIBAwYKKwYBBAHWeQIEAgSB9ASB8QDvAHUAKXm+8J45OSHw" +
            "VnOfY6V35b5XfZxgCvj5TV0mXCVdx4QAAAF4SncFdwAABAMARjBEAiBg+4KXlC4IvmhxXDLWm75ZhJBYKcIrrog9kkwvDrK21QIgMv" +
            "EH52LjDBKfX9y5pQvLjeaNqSpt7zvcQ4xsOOaPI5oAdgAiRUUHWVUkVpY/oS/x922G4CMmY63AS39dxoNcbuIPAgAAAXhKdwXOAAA" +
            "EAwBHMEUCIQCNiVIUyPrlSxBl7s24p9tiRdNhtKdajOwiPbA3zFsemAIgOCaIoCfKwysXVFlY3TuNX5MD8OwSfnMkoZ6nWgwayFcwD" +
            "QYJKoZIhvcNAQELBQADggEBAIOh0LyorneF+6hM3cJgqyaKuAqD+zDCqrU1eGKJrpflWBBT69j4Nvq7ifpSpKHRdig08afxujMx7JXZ" +
            "JOf5Uh8ESiFig3PpipD2NLfYxkuBGSTxZVq2M1qHBL1jqOQQ6oLusXrOPhXfiOUl0H12MgbKXih31ezqPctRpDEOXCaZ6oaToaCf4v" +
            "ZUetR+N4/cMy9fq8bhgTjZj0NLr7cEKIU7zwZUkDF8UxI4bpGOiyXbJzxCzMoQZQlDP2U15hKz3QYCOvWcgoHdFFR0u3t2s+Xf2aGz" +
            "r3r31mgHFdTwkN8OZgQ/3+8fk3c2WR/3hVD2bPPKywJRqYrp+kDqM3RYv34=";
        X509Certificate certificate1 = X509CertUtils.parse(X509CertUtils.PEM_BEGIN_MARKER
            + cert1
            + X509CertUtils.PEM_END_MARKER);
        PublicKey publicKey1 = certificate1.getPublicKey();
        X509Certificate certificate2 = X509CertUtils.parse(X509CertUtils.PEM_BEGIN_MARKER
            + cert2
            + X509CertUtils.PEM_END_MARKER);
        PublicKey publicKey2 = certificate2.getPublicKey();
        CertificateUtils certificateUtils = new CertificateUtils();

        System.out.println(certificateUtils.getCertKid(certificate1)
            +":"+Base64.getEncoder().encodeToString(publicKey1.getEncoded())
            +":"+certificateUtils.getCertKid(certificate2)
                +":"+Base64.getEncoder().encodeToString(publicKey2.getEncoded()));
    }
}
