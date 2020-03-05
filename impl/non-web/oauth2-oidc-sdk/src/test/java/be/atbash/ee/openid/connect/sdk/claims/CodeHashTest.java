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
package be.atbash.ee.openid.connect.sdk.claims;


import be.atbash.ee.oauth2.sdk.AuthorizationCode;
import be.atbash.ee.oauth2.sdk.ResponseType;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the authorisation code hash.
 */
public class CodeHashTest {

    @Test
    public void testComputeAgainstSpecExample() {

        AuthorizationCode code = new AuthorizationCode("Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk");

        CodeHash computedHash = CodeHash.compute(code, JWSAlgorithm.RS256);

        CodeHash expectedHash = new CodeHash("LDktKdoQak3Pk0cnXxCltA");

        assertThat(computedHash.getValue()).isEqualTo(expectedHash.getValue());
    }

    @Test
    public void testEquality() {

        AuthorizationCode code = new AuthorizationCode();

        CodeHash hash1 = CodeHash.compute(code, JWSAlgorithm.HS512);

        CodeHash hash2 = CodeHash.compute(code, JWSAlgorithm.HS512);

        assertThat(hash1.equals(hash2)).isTrue();
    }

    @Test
    public void testUnsupportedJWSAlg() {

        AuthorizationCode code = new AuthorizationCode();

        assertThat(CodeHash.compute(code, new JWSAlgorithm("no-such-alg"))).isNull();
    }

    @Test
    public void testIDTokenRequirement()
            throws Exception {

        // code flow
        // http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
        assertThat(CodeHash.isRequiredInIDTokenClaims(ResponseType.parse("code"))).isFalse();

        // implicit flow
        // http://openid.net/specs/openid-connect-core-1_0.html#ImplicitIDToken
        assertThat(CodeHash.isRequiredInIDTokenClaims(ResponseType.parse("id_token"))).isFalse();
        assertThat(CodeHash.isRequiredInIDTokenClaims(ResponseType.parse("id_token token"))).isFalse();

        // hybrid flow
        // http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
        assertThat(CodeHash.isRequiredInIDTokenClaims(ResponseType.parse("code id_token"))).isTrue();
        assertThat(CodeHash.isRequiredInIDTokenClaims(ResponseType.parse("code token"))).isFalse();
        assertThat(CodeHash.isRequiredInIDTokenClaims(ResponseType.parse("code id_token token"))).isTrue();
    }
}
