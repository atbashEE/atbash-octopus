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


import be.atbash.ee.oauth2.sdk.ResponseType;
import be.atbash.ee.oauth2.sdk.token.AccessToken;
import be.atbash.ee.oauth2.sdk.token.TypelessAccessToken;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests the access token hash.
 */
public class AccessTokenHashTest {

    @Test
    public void testComputeAgainstSpecExample()
            throws Exception {

        AccessToken token = new TypelessAccessToken("jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y");

        AccessTokenHash computedHash = AccessTokenHash.compute(token, JWSAlgorithm.RS256);

        assertThat(computedHash).isNotNull();

        AccessTokenHash expectedHash = new AccessTokenHash("77QmUPtjPfzWtF2AnpK9RQ");

        assertThat(computedHash.getValue()).isEqualTo(expectedHash.getValue());
    }

    @Test
    public void testEquality() {

        AccessToken token = new TypelessAccessToken("12345678");

        AccessTokenHash hash1 = AccessTokenHash.compute(token, JWSAlgorithm.HS512);

        AccessTokenHash hash2 = AccessTokenHash.compute(token, JWSAlgorithm.HS512);

        assertThat(hash1).isNotNull();

        assertThat(hash2).isNotNull();

        assertThat(hash1.equals(hash2)).isTrue();
    }

    @Test
    public void testUnsupportedJWSAlg() {

        AccessToken token = new TypelessAccessToken("12345678");

        assertThat(AccessTokenHash.compute(token, new JWSAlgorithm("no-such-alg"))).isNull();
    }

    @Test
    public void testIDTokenRequirement()
            throws Exception {

        // code flow
        // http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
        assertThat(AccessTokenHash.isRequiredInIDTokenClaims(ResponseType.parse("code"))).isFalse();

        // implicit flow
        // http://openid.net/specs/openid-connect-core-1_0.html#ImplicitIDToken
        assertThat(AccessTokenHash.isRequiredInIDTokenClaims(ResponseType.parse("id_token"))).isFalse();
        assertThat(AccessTokenHash.isRequiredInIDTokenClaims(ResponseType.parse("id_token token"))).isTrue();

        // hybrid flow
        // http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
        assertThat(AccessTokenHash.isRequiredInIDTokenClaims(ResponseType.parse("code id_token"))).isFalse();
        assertThat(AccessTokenHash.isRequiredInIDTokenClaims(ResponseType.parse("code token"))).isFalse();
        assertThat(AccessTokenHash.isRequiredInIDTokenClaims(ResponseType.parse("code id_token token"))).isTrue();
    }
}
