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
package be.atbash.ee.openid.connect.sdk.validators;


import be.atbash.ee.oauth2.sdk.AuthorizationCode;
import be.atbash.ee.openid.connect.sdk.claims.CodeHash;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests the code validator.
 */
public class AuthorizationCodeValidatorTest {

    @Test
    public void testSuccess()
            throws InvalidHashException {

        AuthorizationCode code = new AuthorizationCode(16);
        CodeHash codeHash = CodeHash.compute(code, JWSAlgorithm.RS256);
        AuthorizationCodeValidator.validate(code, JWSAlgorithm.RS256, codeHash);
    }

    @Test
    public void testUnsupportedAlg() {

        AuthorizationCode code = new AuthorizationCode(16);
        CodeHash codeHash = CodeHash.compute(code, JWSAlgorithm.RS256);

        InvalidHashException exception = Assertions.assertThrows(InvalidHashException.class, () ->
                AuthorizationCodeValidator.validate(code, new JWSAlgorithm("none"), codeHash));

        assertThat(exception.getMessage()).isEqualTo("Authorization code hash (c_hash) mismatch");

    }

    @Test
    public void testInvalidHash() {

        AuthorizationCode code = new AuthorizationCode(16);
        InvalidHashException exception = Assertions.assertThrows(InvalidHashException.class, () ->
                AuthorizationCodeValidator.validate(code, JWSAlgorithm.RS256, new CodeHash("xxx")));

        assertThat(exception.getMessage()).isEqualTo("Authorization code hash (c_hash) mismatch");

    }
}
