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
package be.atbash.ee.oauth2.sdk.assertions.jwt;


import be.atbash.ee.oauth2.sdk.BadJWTException;
import be.atbash.ee.oauth2.sdk.id.Audience;
import be.atbash.ee.oauth2.sdk.util.CollectionUtils;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;

import java.util.Set;


/**
 * JSON Web Token (JWT) bearer assertion details (claims set) verifier for
 * OAuth 2.0 client authentication and authorisation grants. Intended for
 * initial validation of JWT assertions:
 *
 * <ul>
 *     <li>Audience check
 *     <li>Expiration time check
 *     <li>Not-before time check (is set)
 *     <li>Subject and issuer presence check
 * </ul>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7523).
 * </ul>
 */
public class JWTAssertionDetailsVerifier extends DefaultJWTClaimsVerifier {


    // Cache JWT exceptions for quick processing of bad claims sets


    /**
     * Missing JWT expiration claim.
     */
    private static final BadJWTException MISSING_EXP_CLAIM_EXCEPTION =
            new BadJWTException("Missing JWT expiration claim");


    /**
     * Missing JWT audience claim.
     */
    private static final BadJWTException MISSING_AUD_CLAIM_EXCEPTION =
            new BadJWTException("Missing JWT audience claim");


    /**
     * Missing JWT subject claim.
     */
    private static final BadJWTException MISSING_SUB_CLAIM_EXCEPTION =
            new BadJWTException("Missing JWT subject claim");


    /**
     * Missing JWT issuer claim.
     */
    private static final BadJWTException MISSING_ISS_CLAIM_EXCEPTION =
            new BadJWTException("Missing JWT issuer claim");


    /**
     * The expected audience.
     */
    private final Set<Audience> expectedAudience;


    /**
     * Creates a new JWT bearer assertion details (claims set) verifier.
     *
     * @param expectedAudience The expected audience (aud) claim values.
     *                         Must not be empty or {@code null}. Should
     *                         typically contain the token endpoint URI and
     *                         for OpenID provider it may also include the
     *                         issuer URI.
     */
    public JWTAssertionDetailsVerifier(final Set<Audience> expectedAudience) {

        if (CollectionUtils.isEmpty(expectedAudience)) {
            throw new IllegalArgumentException("The expected audience set must not be null or empty");
        }

        this.expectedAudience = expectedAudience;
    }


    /**
     * Returns the expected audience values.
     *
     * @return The expected audience (aud) claim values.
     */
    public Set<Audience> getExpectedAudience() {

        return expectedAudience;
    }


    public void verify(final JWTClaimsSet claimsSet)
            throws BadJWTException {

        super.verify(claimsSet);

        if (claimsSet.getExpirationTime() == null) {
            throw MISSING_EXP_CLAIM_EXCEPTION;
        }

        if (claimsSet.getAudience() == null || claimsSet.getAudience().isEmpty()) {
            throw MISSING_AUD_CLAIM_EXCEPTION;
        }

        boolean audMatch = false;

        for (String aud : claimsSet.getAudience()) {

            if (aud == null || aud.isEmpty()) {
                continue; // skip
            }

            if (expectedAudience.contains(new Audience(aud))) {
                audMatch = true;
            }
        }

        if (!audMatch) {
            throw new BadJWTException("Invalid JWT audience claim, expected " + expectedAudience);
        }

        if (claimsSet.getIssuer() == null) {
            throw MISSING_ISS_CLAIM_EXCEPTION;
        }

        if (claimsSet.getSubject() == null) {
            throw MISSING_SUB_CLAIM_EXCEPTION;
        }
    }
}
