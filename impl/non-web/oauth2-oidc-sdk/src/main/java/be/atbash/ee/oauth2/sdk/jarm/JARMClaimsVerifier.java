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
package be.atbash.ee.oauth2.sdk.jarm;


import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.security.octopus.jwt.decoder.JWTVerifier;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.util.DateUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.List;


/**
 * JSON Web Token (JWT) encoded authorisation response claims verifier.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Financial-grade API: JWT Secured Authorization Response Mode for
 *         OAuth 2.0 (JARM).
 * </ul>
 */
public class JARMClaimsVerifier implements JWTVerifier {

    private Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * The expected Authorisation Server.
     */
    private final Issuer expectedIssuer;


    /**
     * The requesting client (for the JWT audience).
     */
    private final ClientID expectedClientID;


    /**
     * The maximum acceptable clock skew, in seconds.
     */
    private int maxClockSkew;


    /**
     * Creates a new ID token claims verifier.
     *
     * @param issuer       The expected Authorisation Server. Must not be
     *                     {@code null}.
     * @param clientID     The client ID. Must not be {@code null}.
     * @param maxClockSkew The maximum acceptable clock skew (absolute
     *                     value), in seconds. Must be zero (no clock skew)
     *                     or positive integer.
     */
    public JARMClaimsVerifier(Issuer issuer,
                              ClientID clientID,
                              int maxClockSkew) {

        if (issuer == null) {
            throw new IllegalArgumentException("The expected ID token issuer must not be null");
        }
        this.expectedIssuer = issuer;

        if (clientID == null) {
            throw new IllegalArgumentException("The client ID must not be null");
        }
        this.expectedClientID = clientID;

        setMaxClockSkew(maxClockSkew);
    }


    /**
     * Returns the expected Authorisation Server.
     *
     * @return The Authorisation Server issuer.
     */
    public Issuer getExpectedIssuer() {

        return expectedIssuer;
    }


    /**
     * Returns the client ID for verifying the JWT audience.
     *
     * @return The client ID.
     */
    public ClientID getClientID() {

        return expectedClientID;
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


    @Override
    public boolean verify(JWSHeader jwsHeader, JWTClaimsSet claimsSet) {

        // See http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation

        String tokenIssuer = claimsSet.getIssuer();

        if (tokenIssuer == null) {
            logger.warn("Missing JWT issuer (iss) claim");  // FIXME Report the offending JWT in some way.
            return false;
        }

        if (!expectedIssuer.getValue().equals(tokenIssuer)) {
            logger.warn("Unexpected JWT issuer: " + tokenIssuer);  // FIXME Report the offending JWT in some way.
            return false;

        }

        List<String> tokenAudience = claimsSet.getAudience();

        if (tokenAudience == null || tokenAudience.isEmpty()) {
            logger.warn("Missing JWT audience (aud) claim");  // FIXME Report the offending JWT in some way.
            return false;

        }

        if (!tokenAudience.contains(expectedClientID.getValue())) {
            logger.warn("Unexpected JWT audience: " + tokenAudience);  // FIXME Report the offending JWT in some way.
            return false;

        }

        Date exp = claimsSet.getExpirationTime();

        if (exp == null) {
            logger.warn("Missing JWT expiration (exp) claim");  // FIXME Report the offending JWT in some way.
            return false;
        }

        Date nowRef = new Date();

        // Expiration must be after current time, given acceptable clock skew
        if (!DateUtils.isAfter(exp, nowRef, maxClockSkew)) {
            logger.warn("Expired JWT");  // FIXME Report the offending JWT in some way.
            return false;
        }
        return true;
    }

}
