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


import be.atbash.ee.oauth2.sdk.BadJWTException;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.openid.connect.sdk.Nonce;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.util.DateUtils;

import java.util.Date;
import java.util.List;


/**
 * ID token claims verifier.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 3.1.3.7 for code flow.
 *     <li>OpenID Connect Core 1.0, section 3.2.2.11 for implicit flow.
 *     <li>OpenID Connect Core 1.0, sections 3.3.2.12 and 3.3.3.7 for hybrid
 *         flow.
 * </ul>
 */
public class IDTokenClaimsVerifier {


    /**
     * The expected ID token issuer.
     */
    private final Issuer expectedIssuer;


    /**
     * The requesting client.
     */
    private final ClientID expectedClientID;


    /**
     * The expected nonce, {@code null} if not required or specified.
     */
    private final Nonce expectedNonce;


    /**
     * The maximum acceptable clock skew, in seconds.
     */
    private int maxClockSkew;


    /**
     * Creates a new ID token claims verifier.
     *
     * @param issuer       The expected ID token issuer. Must not be
     *                     {@code null}.
     * @param clientID     The client ID. Must not be {@code null}.
     * @param nonce        The nonce, required in the implicit flow or for
     *                     ID tokens returned by the authorisation endpoint
     *                     int the hybrid flow. {@code null} if not
     *                     required or specified.
     * @param maxClockSkew The maximum acceptable clock skew (absolute
     *                     value), in seconds. Must be zero (no clock skew)
     *                     or positive integer.
     */
    public IDTokenClaimsVerifier(Issuer issuer,
                                 ClientID clientID,
                                 Nonce nonce,
                                 int maxClockSkew) {

        if (issuer == null) {
            throw new IllegalArgumentException("The expected ID token issuer must not be null");
        }
        this.expectedIssuer = issuer;

        if (clientID == null) {
            throw new IllegalArgumentException("The client ID must not be null");
        }
        this.expectedClientID = clientID;

        this.expectedNonce = nonce;

        setMaxClockSkew(maxClockSkew);
    }


    /**
     * Returns the expected ID token issuer.
     *
     * @return The ID token issuer.
     */
    public Issuer getExpectedIssuer() {

        return expectedIssuer;
    }


    /**
     * Returns the client ID for verifying the ID token audience.
     *
     * @return The client ID.
     */
    public ClientID getClientID() {

        return expectedClientID;
    }


    /**
     * Returns the expected nonce.
     *
     * @return The nonce, {@code null} if not required or specified.
     */
    public Nonce getExpectedNonce() {

        return expectedNonce;
    }


    public int getMaxClockSkew() {

        return maxClockSkew;
    }


    public void setMaxClockSkew(int maxClockSkew) {
        if (maxClockSkew < 0) {
            throw new IllegalArgumentException("The max clock skew must be zero or positive");
        }
        this.maxClockSkew = maxClockSkew;
    }


    public void verify(JWTClaimsSet claimsSet)
            throws BadJWTException {

        // See http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation

        String tokenIssuer = claimsSet.getIssuer();

        if (tokenIssuer == null) {
            throw new BadJWTException("Missing JWT issuer (iss) claim");
        }

        if (!expectedIssuer.getValue().equals(tokenIssuer)) {
            throw new BadJWTException("Unexpected JWT issuer: " + tokenIssuer);
        }

        if (claimsSet.getSubject() == null) {
            throw new BadJWTException("Missing JWT subject (sub) claim");
        }

        List<String> tokenAudience = claimsSet.getAudience();

        if (tokenAudience == null || tokenAudience.isEmpty()) {
            throw new BadJWTException("Missing JWT audience (aud) claim");
        }

        if (!tokenAudience.contains(expectedClientID.getValue())) {
            throw new BadJWTException("Unexpected JWT audience: " + tokenAudience);
        }


        if (tokenAudience.size() > 1) {

            String tokenAzp;

            try {
                tokenAzp = claimsSet.getStringClaim("azp");
            } catch (java.text.ParseException e) {
                throw new BadJWTException("Invalid JWT authorized party (azp) claim: " + e.getMessage());
            }

            if (tokenAzp != null) {
                if (!expectedClientID.getValue().equals(tokenAzp)) {
                    throw new BadJWTException("Unexpected JWT authorized party (azp) claim: " + tokenAzp);
                }
            }
        }

        Date exp = claimsSet.getExpirationTime();

        if (exp == null) {
            throw new BadJWTException("Missing JWT expiration (exp) claim");
        }

        Date iat = claimsSet.getIssueTime();

        if (iat == null) {
            throw new BadJWTException("Missing JWT issue time (iat) claim");
        }


        Date nowRef = new Date();

        // Expiration must be after current time, given acceptable clock skew
        if (!DateUtils.isAfter(exp, nowRef, maxClockSkew)) {
            throw new BadJWTException("Expired JWT");
        }

        // Issue time must be before current time, given acceptable clock skew
        if (!DateUtils.isBefore(iat, nowRef, maxClockSkew)) {
            throw new BadJWTException("JWT issue time ahead of current time");
        }


        if (expectedNonce != null) {

            String tokenNonce;

            try {
                tokenNonce = claimsSet.getStringClaim("nonce");
            } catch (java.text.ParseException e) {
                throw new BadJWTException("Invalid JWT nonce (nonce) claim: " + e.getMessage());
            }

            if (tokenNonce == null) {
                throw new BadJWTException("Missing JWT nonce (nonce) claim");
            }

            if (!expectedNonce.getValue().equals(tokenNonce)) {
                throw new BadJWTException("Unexpected JWT nonce (nonce) claim: " + tokenNonce);
            }
        }
    }
}
