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


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.assertions.AssertionDetails;
import be.atbash.ee.oauth2.sdk.id.*;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.util.DateUtils;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;
import java.util.*;


/**
 * JSON Web Token (JWT) bearer assertion details (claims set) for OAuth 2.0
 * client authentication and authorisation grants.
 *
 * <p>Used for {@link be.atbash.ee.oauth2.sdk.auth.ClientSecretJWT client secret JWT} and
 * {@link be.atbash.ee.oauth2.sdk.auth.PrivateKeyJWT private key JWT} authentication at the Token endpoint
 * as well as {@link be.atbash.ee.oauth2.sdk.JWTBearerGrant JWT bearer
 * assertion grants}.
 *
 * <p>Example JWT bearer assertion claims set for client authentication:
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
 *     <li>JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7523), section 3.
 * </ul>
 */

public class JWTAssertionDetails extends AssertionDetails {


    /**
     * The names of the reserved JWT claims.
     */
    private static final Set<String> reservedClaimsNames = new LinkedHashSet<>();


    static {
        reservedClaimsNames.add("iss");
        reservedClaimsNames.add("sub");
        reservedClaimsNames.add("aud");
        reservedClaimsNames.add("exp");
        reservedClaimsNames.add("nbf");
        reservedClaimsNames.add("iat");
        reservedClaimsNames.add("jti");
    }


    /**
     * Gets the names of the reserved JWT bearer assertion claims.
     *
     * @return The names of the reserved JWT bearer assertion claims
     * (read-only set).
     */
    public static Set<String> getReservedClaimsNames() {

        return Collections.unmodifiableSet(reservedClaimsNames);
    }


    /**
     * The time before which this token must not be accepted for
     * processing (optional). The serialised value is number of seconds
     * from 1970-01-01T0:0:0Z as measured in UTC until the desired
     * date/time.
     */
    private final Date nbf;


    /**
     * Other optional custom claims.
     */
    private final Map<String, Object> other;


    /**
     * Creates a new JWT bearer assertion details (claims set) instance.
     * The expiration time (exp) is set to five minutes from the current
     * system time. Generates a default identifier (jti) for the JWT. The
     * issued-at (iat) and not-before (nbf) claims are not set.
     *
     * @param iss The issuer identifier. Must not be {@code null}.
     * @param sub The subject. Must not be {@code null}.
     * @param aud The audience identifier, typically the URI of the
     *            authorisation server's Token endpoint. Must not be
     *            {@code null}.
     */
    public JWTAssertionDetails(Issuer iss,
                               Subject sub,
                               Audience aud) {

        this(iss, sub, aud.toSingleAudienceList(), new Date(new Date().getTime() + 5 * 60 * 1000L), null, null, new JWTID(), null);
    }


    /**
     * Creates a new JWT bearer assertion details (claims set) instance.
     *
     * @param iss   The issuer identifier. Must not be {@code null}.
     * @param sub   The subject. Must not be {@code null}.
     * @param aud   The audience, typically including the URI of the
     *              authorisation server's token endpoint. Must not be
     *              {@code null}.
     * @param exp   The expiration time. Must not be {@code null}.
     * @param nbf   The time before which the token must not be accepted
     *              for processing, {@code null} if not specified.
     * @param iat   The time at which the token was issued, {@code null} if
     *              not specified.
     * @param jti   Unique identifier for the JWT, {@code null} if not
     *              specified.
     * @param other Other custom claims to include, {@code null} if none.
     */
    public JWTAssertionDetails(Issuer iss,
                               Subject sub,
                               List<Audience> aud,
                               Date exp,
                               Date nbf,
                               Date iat,
                               JWTID jti,
                               Map<String, Object> other) {

        super(iss, sub, aud, iat, exp, jti);
        this.nbf = nbf;
        this.other = other;
    }


    /**
     * Returns the optional not-before time. Corresponds to the {@code nbf}
     * claim.
     *
     * @return The not-before time, {@code null} if not specified.
     */
    public Date getNotBeforeTime() {

        return nbf;
    }


    /**
     * Returns the optional assertion identifier, as a JWT ID. Corresponds
     * to the {@code jti} claim.
     *
     * @return The optional JWT ID, {@code null} if not specified.
     * @see #getID()
     */
    public JWTID getJWTID() {

        Identifier id = getID();
        return id != null ? new JWTID(id.getValue()) : null;
    }


    /**
     * Returns the custom claims.
     *
     * @return The custom claims, {@code null} if not specified.
     */
    public Map<String, Object> getCustomClaims() {

        return other;
    }


    /**
     * Returns a JSON object representation of this JWT bearer assertion
     * details.
     *
     * @return The JSON object.
     */
    public JsonObject toJSONObject() {

        JsonObjectBuilder result = Json.createObjectBuilder();

        result.add("iss", getIssuer().getValue());
        result.add("sub", getSubject().getValue());
        result.add("aud", JSONObjectUtils.asJsonArray(Audience.toStringList(getAudience())));
        result.add("exp", DateUtils.toSecondsSinceEpoch(getExpirationTime()));

        if (nbf != null) {
            result.add("nbf", DateUtils.toSecondsSinceEpoch(nbf));
        }

        if (getIssueTime() != null) {
            result.add("iat", DateUtils.toSecondsSinceEpoch(getIssueTime()));
        }

        if (getID() != null) {
            result.add("jti", getID().getValue());
        }

        if (other != null) {
            for (Map.Entry<String, Object> entry : other.entrySet()) {
                JSONObjectUtils.addValue(result, entry.getKey(), entry.getValue());

            }

        }

        return result.build();
    }


    /**
     * Returns a JSON Web Token (JWT) claims set representation of this
     * JWT bearer assertion details.
     *
     * @return The JWT claims set.
     */
    public JWTClaimsSet toJWTClaimsSet() {

        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(getIssuer().getValue())
                .subject(getSubject().getValue())
                .audience(Audience.toStringList(getAudience()))
                .expirationTime(getExpirationTime())
                .notBeforeTime(nbf) // optional
                .issueTime(getIssueTime()) // optional
                .jwtID(getID() != null ? getJWTID().getValue() : null); // optional

        // Append custom claims if any
        if (other != null) {
            for (Map.Entry<String, ?> entry : other.entrySet()) {
                builder = builder.claim(entry.getKey(), entry.getValue());
            }
        }

        return builder.build();
    }


    /**
     * Parses a JWT bearer assertion details (claims set) instance from the
     * specified JSON object.
     *
     * @param jsonObject The JSON object. Must not be {@code null}.
     * @return The JWT bearer assertion details.
     */
    public static JWTAssertionDetails parse(JsonObject jsonObject) {

        // Parse required claims
        Issuer iss = new Issuer(jsonObject.getString("iss"));
        Subject sub = new Subject(jsonObject.getString("sub"));

        List<Audience> aud;

        if (jsonObject.get("aud").getValueType() == JsonValue.ValueType.STRING) {
            aud = new Audience(jsonObject.getString("aud")).toSingleAudienceList();
        } else {
            aud = Audience.create(JSONObjectUtils.getStringList(jsonObject, "aud"));
        }

        Date exp = DateUtils.fromSecondsSinceEpoch(jsonObject.getJsonNumber("exp").longValue());


        // Parse optional claims

        Date nbf = null;

        if (jsonObject.containsKey("nbf")) {
            nbf = DateUtils.fromSecondsSinceEpoch(jsonObject.getJsonNumber("nbf").longValue());
        }

        Date iat = null;

        if (jsonObject.containsKey("iat")) {
            iat = DateUtils.fromSecondsSinceEpoch(jsonObject.getJsonNumber("iat").longValue());
        }

        JWTID jti = null;

        if (jsonObject.containsKey("jti")) {
            jti = new JWTID(jsonObject.getString("jti"));
        }

        // Parse custom claims
        Map<String, Object> other = null;

        Set<String> customClaimNames = new HashSet<>(jsonObject.keySet());
        if (customClaimNames.removeAll(reservedClaimsNames)) {
            other = new LinkedHashMap<>();
            for (String claim : customClaimNames) {
                other.put(claim, jsonObject.get(claim));
            }
        }

        return new JWTAssertionDetails(iss, sub, aud, exp, nbf, iat, jti, other);
    }


    /**
     * Parses a JWT bearer assertion details instance from the specified
     * JWT claims set.
     *
     * @param jwtClaimsSet The JWT claims set. Must not be {@code null}.
     * @return The JWT bearer assertion details.
     * @throws OAuth2JSONParseException If the JWT claims set couldn't be parsed to a
     *                                  JWT bearer assertion details instance.
     */
    public static JWTAssertionDetails parse(JWTClaimsSet jwtClaimsSet)
            throws OAuth2JSONParseException {

        return parse(jwtClaimsSet.toJSONObject());
    }
}
