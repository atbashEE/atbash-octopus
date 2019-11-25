/*
 * Copyright 2014-2019 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.openid.connect.sdk.validators;


import be.atbash.ee.oauth2.sdk.token.AccessToken;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;
import be.atbash.ee.openid.connect.sdk.claims.AccessTokenHash;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;

/**
 * Tests the access token hash validator.
 */
public class AccessTokenValidatorTest {

    @Test
    public void testValid()
            throws InvalidHashException {

        AccessToken token = new BearerAccessToken(32);
        AccessTokenHash atHash = AccessTokenHash.compute(token, JWSAlgorithm.HS256);
        AccessTokenValidator.validate(token, JWSAlgorithm.HS256, atHash);
    }

    @Test
    public void testUnsupportedAlg() {

        AccessToken token = new BearerAccessToken(32);
        AccessTokenHash atHash = AccessTokenHash.compute(token, JWSAlgorithm.HS256);
        try {
            AccessTokenValidator.validate(token, new JWSAlgorithm("none"), atHash);
            fail();
        } catch (InvalidHashException e) {
            assertThat(e.getMessage()).isEqualTo("Access token hash (at_hash) mismatch");
        }
    }

    @Test
    public void testInvalidHash() {

        AccessToken token = new BearerAccessToken(32);
        try {
            AccessTokenValidator.validate(token, JWSAlgorithm.HS256, new AccessTokenHash("xxx"));
            fail();
        } catch (InvalidHashException e) {
            assertThat(e.getMessage()).isEqualTo("Access token hash (at_hash) mismatch");
        }
    }
}
