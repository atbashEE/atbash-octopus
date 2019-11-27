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
package be.atbash.ee.oauth2.sdk.auth.verifier;


import be.atbash.ee.oauth2.sdk.BadJWTException;
import be.atbash.ee.oauth2.sdk.assertions.jwt.JWTAssertionDetailsVerifier;
import be.atbash.ee.oauth2.sdk.id.Audience;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;

import java.util.Set;


/**
 * JWT client authentication claims set verifier.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 9.
 *     <li>JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7523).
 * </ul>
 */
class JWTAuthenticationClaimsSetVerifier extends JWTAssertionDetailsVerifier {

    // Cache JWT exceptions for quick processing of bad claims

    /**
     * Missing or invalid JWT claim exception.
     */
    private static final BadJWTException ISS_SUB_MISMATCH_EXCEPTION =
            new BadJWTException("Issuer and subject JWT claims don't match");


    /**
     * Creates a new JWT client authentication claims set verifier.
     *
     * @param expectedAudience The permitted audience (aud) claim values.
     *                         Must not be empty or {@code null}. Should
     *                         typically contain the token endpoint URI and
     *                         for OpenID provider it may also include the
     *                         issuer URI.
     */
    public JWTAuthenticationClaimsSetVerifier(Set<Audience> expectedAudience) {

        super(expectedAudience);
    }


    @Override
    public void verify(JWTClaimsSet claimsSet)
            throws BadJWTException {

        super.verify(claimsSet);

        // iss == sub
        if (!claimsSet.getIssuer().equals(claimsSet.getSubject())) {
            throw ISS_SUB_MISMATCH_EXCEPTION;
        }
    }
}
