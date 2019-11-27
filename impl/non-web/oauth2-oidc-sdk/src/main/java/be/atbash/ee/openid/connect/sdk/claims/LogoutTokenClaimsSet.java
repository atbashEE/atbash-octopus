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
package be.atbash.ee.openid.connect.sdk.claims;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.id.Audience;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.oauth2.sdk.id.JWTID;
import be.atbash.ee.oauth2.sdk.id.Subject;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;

import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.text.ParseException;
import java.util.*;


/**
 * Back-channel logout token claims set, serialisable to a JSON object.
 *
 * <p>Example logout token claims set:
 *
 * <pre>o
 * {
 *   "iss"    : "https://server.example.com",
 *   "sub"    : "248289761001",
 *   "aud"    : "s6BhdRkqt3",
 *   "iat"    : 1471566154,
 *   "jti"    : "bWJq",
 *   "sid"    : "08a5019c-17e1-4977-8f42-65a12843ea02",
 *   "events" : { "http://schemas.openid.net/event/backchannel-logout": { } }
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Back-Channel Logout 1.0, section 2.4 (draft 04).
 *     <li>Security Event Token (SET) (RFC 8417)
 * </ul>
 */
// FIXME Will this be used in Octopus?
public class LogoutTokenClaimsSet extends CommonClaimsSet {


    /**
     * The JWT ID claim name.
     */
    public static final String JTI_CLAIM_NAME = "jti";


    /**
     * The events claim name.
     */
    public static final String EVENTS_CLAIM_NAME = "events";


    /**
     * The OpenID logout event type.
     */
    public static final String EVENT_TYPE = "http://schemas.openid.net/event/backchannel-logout";


    /**
     * The names of the standard top-level ID token claims.
     */
    private static final Set<String> stdClaimNames = new LinkedHashSet<>();


    static {
        stdClaimNames.add(ISS_CLAIM_NAME);
        stdClaimNames.add(SUB_CLAIM_NAME);
        stdClaimNames.add(AUD_CLAIM_NAME);
        stdClaimNames.add(IAT_CLAIM_NAME);
        stdClaimNames.add(JTI_CLAIM_NAME);
        stdClaimNames.add(EVENTS_CLAIM_NAME);
        stdClaimNames.add(SID_CLAIM_NAME);
    }


    /**
     * Gets the names of the standard top-level logout token claims.
     *
     * @return The names of the standard top-level logout token claims
     * (read-only set).
     */
    public static Set<String> getStandardClaimNames() {

        return Collections.unmodifiableSet(stdClaimNames);
    }


    /**
     * Creates a new logout token claims set. Either the subject or the
     * session ID must be set, or both.
     *
     * @param iss The issuer. Must not be {@code null}.
     * @param sub The subject. Must not be {@code null} unless the session
     *            ID is set.
     * @param aud The audience. Must not be {@code null}.
     * @param iat The issue time. Must not be {@code null}.
     * @param jti The JWT ID. Must not be {@code null}.
     * @param sid The session ID. Must not be {@code null} unless the
     *            subject is set.
     */
    public LogoutTokenClaimsSet(Issuer iss,
                                Subject sub,
                                List<Audience> aud,
                                Date iat,
                                JWTID jti,
                                SessionID sid) {

        if (sub == null && sid == null) {
            throw new IllegalArgumentException("Either the subject or the session ID must be set, or both");
        }

        setClaim(ISS_CLAIM_NAME, iss.getValue());

        if (sub != null) {
            setClaim(SUB_CLAIM_NAME, sub.getValue());
        }

        JsonArrayBuilder audList = Json.createArrayBuilder();

        for (Audience a : aud) {
            audList.add(a.getValue());
        }

        setClaim(AUD_CLAIM_NAME, audList.build());

        setDateClaim(IAT_CLAIM_NAME, iat);

        setClaim(JTI_CLAIM_NAME, jti.getValue());

        JsonObjectBuilder events = Json.createObjectBuilder();
        events.add(EVENT_TYPE, Json.createObjectBuilder().build());
        setClaim(EVENTS_CLAIM_NAME, events.build());

        if (sid != null) {
            setClaim(SID_CLAIM_NAME, sid.getValue());
        }
    }


    /**
     * Creates a new logout token claims set from the specified JSON
     * object.
     *
     * @param jsonObject The JSON object. Must be verified to represent a
     *                   valid logout token claims set and not be
     *                   {@code null}.
     * @throws OAuth2JSONParseException If the JSON object doesn't represent a valid
     *                                  logout token claims set.
     */
    private LogoutTokenClaimsSet(JsonObject jsonObject)
            throws OAuth2JSONParseException {

        super(jsonObject);

        if (getStringClaim(ISS_CLAIM_NAME) == null) {
            throw new OAuth2JSONParseException("Missing or invalid \"iss\" claim");
        }

        if (getStringClaim(SUB_CLAIM_NAME) == null && getStringClaim(SID_CLAIM_NAME) == null) {
            throw new OAuth2JSONParseException("Missing or invalid \"sub\" and / or \"sid\" claim(s)");
        }

        if (getStringClaim(AUD_CLAIM_NAME) == null && getStringListClaim(AUD_CLAIM_NAME) == null ||
                getStringListClaim(AUD_CLAIM_NAME) != null && getStringListClaim(AUD_CLAIM_NAME).isEmpty()) {
            throw new OAuth2JSONParseException("Missing or invalid \"aud\" claim");
        }

        if (getDateClaim(IAT_CLAIM_NAME) == null) {
            throw new OAuth2JSONParseException("Missing or invalid \"iat\" claim");
        }

        if (getStringClaim(JTI_CLAIM_NAME) == null) {
            throw new OAuth2JSONParseException("Missing or invalid \"jti\" claim");
        }

        if (getClaim(EVENTS_CLAIM_NAME) == null) {
            throw new OAuth2JSONParseException("Missing or invalid \"events\" claim");
        }

        JsonObject events = (JsonObject) getClaim(EVENTS_CLAIM_NAME);

        if (!events.containsKey(EVENT_TYPE)) {
            throw new OAuth2JSONParseException("Missing event type " + EVENT_TYPE);
        }

        if (jsonObject.containsKey("nonce")) {
            throw new OAuth2JSONParseException("Nonce is prohibited");
        }
    }


    /**
     * Creates a new logout token claims set from the specified JSON Web
     * Token (JWT) claims set.
     *
     * @param jwtClaimsSet The JWT claims set. Must not be {@code null}.
     * @throws OAuth2JSONParseException If the JWT claims set doesn't represent a
     *                                  valid logout token claims set.
     */
    public LogoutTokenClaimsSet(JWTClaimsSet jwtClaimsSet)
            throws OAuth2JSONParseException {

        this(jwtClaimsSet.toJSONObject());
    }


    /**
     * Gets the JWT ID. Corresponds to the {@code jti} claim.
     *
     * @return The JWT ID.
     */
    public JWTID getJWTID() {

        return new JWTID(getStringClaim(JTI_CLAIM_NAME));
    }


    @Override
    public JsonObjectBuilder toJSONObject() {

        if (getClaim("nonce") != null) {
            throw new IllegalStateException("Nonce is prohibited");
        }

        return super.toJSONObject();
    }


    @Override
    public JWTClaimsSet toJWTClaimsSet()
            throws OAuth2JSONParseException {

        if (getClaim("nonce") != null) {
            throw new OAuth2JSONParseException("Nonce is prohibited");
        }

        return super.toJWTClaimsSet();
    }


    /**
     * Parses a logout token claims set from the specified JSON object
     * string.
     *
     * @param json The JSON object string to parse. Must not be
     *             {@code null}.
     * @return The logout token claims set.
     * @throws OAuth2JSONParseException If parsing failed.
     */
    public static LogoutTokenClaimsSet parse(String json)
            throws OAuth2JSONParseException {

        JsonObject jsonObject;
        try {
            jsonObject = JSONObjectUtils.parse(json);
        } catch (ParseException e) {
            throw new OAuth2JSONParseException(e.getMessage(), e);
        }

        try {
            return new LogoutTokenClaimsSet(jsonObject);

        } catch (IllegalArgumentException e) {

            throw new OAuth2JSONParseException(e.getMessage(), e);
        }
    }
}
