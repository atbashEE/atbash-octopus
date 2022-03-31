/*
 * Copyright 2014-2020 Rudy De Busscher (https://www.atbash.be)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package be.atbash.ee.oauth2.sdk.auth;


import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.ByteUtils;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import be.atbash.ee.security.octopus.nimbus.util.X509CertUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import jakarta.json.JsonObject;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;


public class X509CertificateConfirmationTest {


    private static final String PEM_CERT = "-----BEGIN CERTIFICATE-----" +
            "MIICUTCCAfugAwIBAgIBADANBgkqhkiG9w0BAQQFADBXMQswCQYDVQQGEwJDTjEL" +
            "MAkGA1UECBMCUE4xCzAJBgNVBAcTAkNOMQswCQYDVQQKEwJPTjELMAkGA1UECxMC" +
            "VU4xFDASBgNVBAMTC0hlcm9uZyBZYW5nMB4XDTA1MDcxNTIxMTk0N1oXDTA1MDgx" +
            "NDIxMTk0N1owVzELMAkGA1UEBhMCQ04xCzAJBgNVBAgTAlBOMQswCQYDVQQHEwJD" +
            "TjELMAkGA1UEChMCT04xCzAJBgNVBAsTAlVOMRQwEgYDVQQDEwtIZXJvbmcgWWFu" +
            "ZzBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQCp5hnG7ogBhtlynpOS21cBewKE/B7j" +
            "V14qeyslnr26xZUsSVko36ZnhiaO/zbMOoRcKK9vEcgMtcLFuQTWDl3RAgMBAAGj" +
            "gbEwga4wHQYDVR0OBBYEFFXI70krXeQDxZgbaCQoR4jUDncEMH8GA1UdIwR4MHaA" +
            "FFXI70krXeQDxZgbaCQoR4jUDncEoVukWTBXMQswCQYDVQQGEwJDTjELMAkGA1UE" +
            "CBMCUE4xCzAJBgNVBAcTAkNOMQswCQYDVQQKEwJPTjELMAkGA1UECxMCVU4xFDAS" +
            "BgNVBAMTC0hlcm9uZyBZYW5nggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEE" +
            "BQADQQA/ugzBrjjK9jcWnDVfGHlk3icNRq0oV7Ri32z/+HQX67aRfgZu7KWdI+Ju" +
            "Wm7DCfrPNGVwFWUQOmsPue9rZBgO" +
            "-----END CERTIFICATE-----";

    @Test
    public void testLifeCycle()
            throws Exception {

        X509Certificate clientCert = X509CertUtils.parse(PEM_CERT);

        Base64URLValue x5t = X509CertUtils.computeSHA256Thumbprint(clientCert);
        assertThat(ByteUtils.bitLength(x5t.decode())).isEqualTo(256);

        X509CertificateConfirmation certCnf = new X509CertificateConfirmation(x5t);

        assertThat(certCnf.getValue()).isEqualTo(x5t);

        JsonObject jsonObject = certCnf.toJSONObject();
        JsonObject cnfObject = jsonObject.getJsonObject("cnf");
        assertThat(cnfObject.getString("x5t#S256")).isEqualTo(x5t.toString());
        assertThat(cnfObject).hasSize(1);
        assertThat(jsonObject).hasSize(1);

        certCnf = X509CertificateConfirmation.parse(JWTClaimsSet.parse(jsonObject));
        assertThat(certCnf.getValue()).isEqualTo(x5t);
    }

    @Test
    public void testOf()
            throws Exception {

        X509Certificate clientCert = X509CertUtils.parse(PEM_CERT);

        Base64URLValue x5t = X509CertUtils.computeSHA256Thumbprint(clientCert);
        assertThat(ByteUtils.bitLength(x5t.decode())).isEqualTo(256);

        X509CertificateConfirmation certCnf = X509CertificateConfirmation.of(clientCert);

        JsonObject jsonObject = certCnf.toJSONObject();
        JsonObject cnfObject = jsonObject.getJsonObject("cnf");
        assertThat(cnfObject.getString("x5t#S256")).isEqualTo(x5t.toString());
        assertThat(cnfObject).hasSize(1);  // FIXME
        assertThat(jsonObject).hasSize(1);
    }

    @Test
    public void testApplyToJWTClaimsSet()
            throws Exception {

        X509Certificate clientCert = X509CertUtils.parse(PEM_CERT);

        X509CertificateConfirmation certCnf = X509CertificateConfirmation.of(clientCert);

        JWTClaimsSet jwtClaimsSet = certCnf.applyTo(new JWTClaimsSet.Builder().build());

        JsonObject cnfObject = jwtClaimsSet.getJSONObjectClaim("cnf");
        assertThat(cnfObject.getString("x5t#S256")).isEqualTo(certCnf.getValue().toString());

        assertThat(jwtClaimsSet.getClaims()).hasSize(1);
    }

    @Test
    public void testRejectNullArg() {

        IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class, () -> new X509CertificateConfirmation(null));

        assertThat(exception.getMessage()).isEqualTo("The X.509 certificate thumbprint must not be null");

    }

    @Test
    public void testParse_nullJWTClaimsSet() {

        Assertions.assertThrows(NullPointerException.class, () -> X509CertificateConfirmation.parse((JWTClaimsSet) null));

    }

    @Test
    public void testParse_nullJSONObject() {

        Assertions.assertThrows(NullPointerException.class, () -> X509CertificateConfirmation.parse((JsonObject) null));

    }

    @Test
    public void testParseClaimsSet()
            throws Exception {

        String json = "{\n" +
                "       \"iss\": \"https://server.example.com\",\n" +
                "       \"sub\": \"ty.webb@example.com\",\n" +
                "       \"exp\": 1493726400,\n" +
                "       \"nbf\": 1493722800,\n" +
                "       \"cnf\":{\n" +
                "         \"x5t#S256\": \"bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2\"\n" +
                "       }\n" +
                "     }";

        assertThat(X509CertificateConfirmation.parse(JWTClaimsSet.parse(json)).getValue()).isEqualTo(new Base64URLValue("bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"));

        assertThat(X509CertificateConfirmation.parse(JSONObjectUtils.parse(json)).getValue()).isEqualTo(new Base64URLValue("bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"));
    }

    @Test
    public void testParseX5TMissing()
            throws Exception {

        String json = "{\n" +
                "       \"iss\": \"https://server.example.com\",\n" +
                "       \"sub\": \"ty.webb@example.com\",\n" +
                "       \"exp\": 1493726400,\n" +
                "       \"nbf\": 1493722800,\n" +
                "       \"cnf\":{\n" +
                "       }\n" +
                "     }";

        assertThat(X509CertificateConfirmation.parse(JWTClaimsSet.parse(json))).isNull();

        assertThat(X509CertificateConfirmation.parse(JSONObjectUtils.parse(json))).isNull();
    }

    @Test
    public void testToString() {

        assertThat(new X509CertificateConfirmation(new Base64URLValue("bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2")).toString()).isEqualTo("{\"cnf\":{\"x5t#S256\":\"bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2\"}}");
    }
}
