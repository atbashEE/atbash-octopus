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

import be.atbash.ee.oauth2.sdk.AuthorizationResponse;
import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.oauth2.sdk.util.MultivaluedMapUtils;
import be.atbash.ee.security.octopus.nimbus.jwt.*;

import java.util.*;


/**
 * JWT Secured Authorization Response Mode for OAuth 2.0 (JARM) utilities.
 */
public final class JARMUtils {


    /**
     * Creates a JSON Web Token (JWT) claims set for the specified
     * authorisation success response.
     *
     * @param iss      The OAuth 2.0 authorisation server issuer. Must not
     *                 be {@code null}.
     * @param aud      The client ID. Must not be {@code null}.
     * @param exp      The JWT expiration time. Must not be {@code null}.
     * @param response The plain authorisation response to use its
     *                 parameters. Must not be {@code null}.
     * @return The JWT claims set.
     */
    public static JWTClaimsSet toJWTClaimsSet(Issuer iss,
                                              ClientID aud,
                                              Date exp,
                                              AuthorizationResponse response) {

        if (exp == null) {
            throw new IllegalArgumentException("The expiration time must not be null");
        }

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(iss.getValue())
                .audience(aud.getValue())
                .expirationTime(exp);

        for (Map.Entry<String, ?> en : MultivaluedMapUtils.toSingleValuedMap(response.toParameters()).entrySet()) {

            if ("response".equals(en.getKey())) {
                continue; // own JARM parameter, skip
            }

            builder = builder.claim(en.getKey(), en.getValue().toString());
        }

        return builder.build();
    }


    /**
     * Returns a multi-valued map representation of the specified JWT
     * claims set.
     *
     * @param jwtClaimsSet The JWT claims set. Must not be {@code null}.
     * @return The multi-valued map.
     */
    public static Map<String, List<String>> toMultiValuedStringParameters(JWTClaimsSet jwtClaimsSet) {

        Map<String, List<String>> params = new HashMap<>();

        for (Map.Entry<String, Object> en : jwtClaimsSet.getClaims().entrySet()) {
            params.put(en.getKey(), Collections.singletonList(en.getValue() + ""));
        }

        return params;
    }


    /**
     * Returns {@code true} if the specified JWT-secured authorisation
     * response implies an error response. Note that the JWT is not
     * validated in any way!
     *
     * @param jwtString The JWT-secured authorisation response string. Must
     *                  not be {@code null}.
     * @return {@code true} if an error is implied by the presence of the
     * {@code error} claim, else {@code false} (also for encrypted
     * JWTs which payload cannot be inspected without decrypting
     * first).
     * @throws OAuth2JSONParseException If the JWT is invalid or plain (unsecured).
     */
    public static boolean impliesAuthorizationErrorResponse(String jwtString)
            throws OAuth2JSONParseException {

        try {
            return impliesAuthorizationErrorResponse(JWTParser.parse(jwtString));
        } catch (java.text.ParseException e) {
            throw new OAuth2JSONParseException("Invalid JWT-secured authorization response: " + e.getMessage(), e);
        }
    }


    /**
     * Returns {@code true} if the specified JWT-secured authorisation
     * response implies an error response. Note that the JWT is not
     * validated in any way!
     *
     * @param jwt The JWT-secured authorisation response. Must not be
     *            {@code null}.
     * @return {@code true} if an error is implied by the presence of the
     * {@code error} claim, else {@code false} (also for encrypted
     * JWTs which payload cannot be inspected without decrypting
     * first).
     * @throws OAuth2JSONParseException If the JWT is plain (unsecured).
     */
    public static boolean impliesAuthorizationErrorResponse(JWT jwt)
            throws OAuth2JSONParseException {

        if (jwt instanceof PlainJWT) {
            throw new OAuth2JSONParseException("Invalid JWT-secured authorization response: The JWT must not be plain (unsecured)");
        }

        if (jwt instanceof EncryptedJWT) {
            // Cannot peek into payload
            return false;
        }

        if (jwt instanceof SignedJWT) {

            SignedJWT signedJWT = (SignedJWT) jwt;

            try {
                return signedJWT.getJWTClaimsSet().getStringClaim("error") != null;
            } catch (java.text.ParseException e) {
                throw new OAuth2JSONParseException("Invalid JWT claims set: " + e.getMessage());
            }
        }

        throw new OAuth2JSONParseException("Unexpected JWT type");
    }


    /**
     * Prevents public instantiation.
     */
    private JARMUtils() {
    }
}
