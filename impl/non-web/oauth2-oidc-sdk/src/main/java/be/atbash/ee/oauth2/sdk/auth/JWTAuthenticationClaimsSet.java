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
package be.atbash.ee.oauth2.sdk.auth;


import be.atbash.ee.oauth2.sdk.assertions.jwt.JWTAssertionDetails;
import be.atbash.ee.oauth2.sdk.id.*;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;

import javax.json.JsonObject;
import java.util.Date;
import java.util.List;


/**
 * JWT client authentication claims set, serialisable to a JSON object and JWT
 * claims set.
 *
 * <p>Used for {@link ClientSecretJWT client secret JWT} and
 * {@link PrivateKeyJWT private key JWT} authentication at the Token endpoint.
 *
 * <p>Example client authentication claims set:
 *
 * <pre>
 * {
 *   "iss" : "http://client.example.com",
 *   "sub" : "http://client.example.com",
 *   "aud" : [ "http://idp.example.com/token" ],
 *   "jti" : "d396036d-c4d9-40d8-8e98-f7e8327002d9",
 *   "exp" : 1311281970,
 *   "iat" : 1311280970
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section-3.2.1.
 *     <li>JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7523).
 * </ul>
 */
public class JWTAuthenticationClaimsSet extends JWTAssertionDetails {


    /**
     * Creates a new JWT client authentication claims set. The expiration
     * time (exp) is set to five minutes from the current system time.
     * Generates a default identifier (jti) for the JWT. The issued-at
     * (iat) and not-before (nbf) claims are not set.
     *
     * @param clientID The client identifier. Used to specify the issuer
     *                 and the subject. Must not be {@code null}.
     * @param aud      The audience identifier, typically the URI of the
     *                 authorisation server's Token endpoint. Must not be
     *                 {@code null}.
     */
    public JWTAuthenticationClaimsSet(ClientID clientID,
                                      Audience aud) {

        this(clientID, aud.toSingleAudienceList(), new Date(new Date().getTime() + 5 * 60 * 1000L), null, null, new JWTID());
    }


    /**
     * Creates a new JWT client authentication claims set.
     *
     * @param clientID The client identifier. Used to specify the issuer
     *                 and the subject. Must not be {@code null}.
     * @param aud      The audience, typically including the URI of the
     *                 authorisation server's Token endpoint. Must not be
     *                 {@code null}.
     * @param exp      The expiration time. Must not be {@code null}.
     * @param nbf      The time before which the token must not be
     *                 accepted for processing, {@code null} if not
     *                 specified.
     * @param iat      The time at which the token was issued,
     *                 {@code null} if not specified.
     * @param jti      Unique identifier for the JWT, {@code null} if
     *                 not specified.
     */
    public JWTAuthenticationClaimsSet(ClientID clientID,
                                      List<Audience> aud,
                                      Date exp,
                                      Date nbf,
                                      Date iat,
                                      JWTID jti) {

        super(new Issuer(clientID.getValue()), new Subject(clientID.getValue()), aud, exp, nbf, iat, jti, null);
    }


    /**
     * Gets the client identifier. Corresponds to the {@code iss} and
     * {@code sub} claims.
     *
     * @return The client identifier.
     */
    public ClientID getClientID() {

        return new ClientID(getIssuer());
    }

    /**
     * Parses a JWT client authentication claims set from the specified
     * JSON object.
     *
     * @param jsonObject The JSON object. Must not be {@code null}.
     * @return The client authentication claims set.
     */
    public static JWTAuthenticationClaimsSet parse(JsonObject jsonObject) {

        JWTAssertionDetails assertion = JWTAssertionDetails.parse(jsonObject);

        return new JWTAuthenticationClaimsSet(
                new ClientID(assertion.getIssuer()), // iss=sub
                assertion.getAudience(),
                assertion.getExpirationTime(),
                assertion.getNotBeforeTime(),
                assertion.getIssueTime(),
                assertion.getJWTID());
    }


    /**
     * Parses a JWT client authentication claims set from the specified JWT
     * claims set.
     *
     * @param jwtClaimsSet The JWT claims set. Must not be {@code null}.
     * @return The client authentication claims set.
     */
    public static JWTAuthenticationClaimsSet parse(JWTClaimsSet jwtClaimsSet) {

        return parse(jwtClaimsSet.toJSONObject());
    }
}
