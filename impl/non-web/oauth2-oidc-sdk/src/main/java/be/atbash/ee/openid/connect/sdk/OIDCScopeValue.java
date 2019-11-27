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
package be.atbash.ee.openid.connect.sdk;


import be.atbash.ee.oauth2.sdk.Scope;
import be.atbash.ee.openid.connect.sdk.claims.ClaimRequirement;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.util.*;


/**
 * Standard OpenID Connect scope value.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 5.2.
 * </ul>
 */
public class OIDCScopeValue extends Scope.Value {


    /**
     * Informs the authorisation server that the client is making an OpenID
     * Connect request (REQUIRED). This scope value requests access to the
     * {@code sub} claim.
     */
    public static final OIDCScopeValue OPENID =
            new OIDCScopeValue("openid", Scope.Value.Requirement.REQUIRED, new String[]{"sub"});


    /**
     * Requests that access to the end-user's default profile claims at the
     * UserInfo endpoint be granted by the issued access token. These
     * claims are: {@code name}, {@code family_name}, {@code given_name},
     * {@code middle_name}, {@code nickname}, {@code preferred_username},
     * {@code profile}, {@code picture}, {@code website}, {@code gender},
     * {@code birthdate}, {@code zoneinfo}, {@code locale}, and
     * {@code updated_at}.
     */
    public static final OIDCScopeValue PROFILE =
            new OIDCScopeValue("profile", new String[]{"name",
                    "family_name",
                    "given_name",
                    "middle_name",
                    "nickname",
                    "preferred_username",
                    "profile",
                    "picture",
                    "website",
                    "gender",
                    "birthdate",
                    "zoneinfo",
                    "locale",
                    "updated_at"});


    /**
     * Requests that access to the {@code email} and {@code email_verified}
     * claims at the UserInfo endpoint be granted by the issued access
     * token.
     */
    public static final OIDCScopeValue EMAIL =
            new OIDCScopeValue("email", new String[]{"email", "email_verified"});


    /**
     * Requests that access to {@code address} claim at the UserInfo
     * endpoint be granted by the issued access token.
     */
    public static final OIDCScopeValue ADDRESS =
            new OIDCScopeValue("address", new String[]{"address"});


    /**
     * Requests that access to the {@code phone_number} and
     * {@code phone_number_verified} claims at the UserInfo endpoint be
     * granted by the issued access token.
     */
    public static final OIDCScopeValue PHONE =
            new OIDCScopeValue("phone", new String[]{"phone_number",
                    "phone_number_verified"});


    /**
     * Requests that an OAuth 2.0 refresh token be issued that can be used
     * to obtain an access token that grants access the end-user's UserInfo
     * endpoint even when the user is not present (not logged in).
     */
    public static final OIDCScopeValue OFFLINE_ACCESS =
            new OIDCScopeValue("offline_access", null);


    /**
     * Returns the standard OpenID Connect scope values declared in this
     * class.
     *
     * @return The standard OpenID Connect scope values.
     */
    public static OIDCScopeValue[] values() {

        return new OIDCScopeValue[]{OPENID, PROFILE, EMAIL, ADDRESS, PHONE, OFFLINE_ACCESS};
    }


    /**
     * The names of the associated claims, {@code null} if not applicable.
     */
    private final Set<String> claims;


    /**
     * Creates a new OpenID Connect scope value.
     *
     * @param value       The scope value. Must not be {@code null}.
     * @param requirement The requirement. Must not be {@code null}.
     * @param claims      The names of the associated claims, {@code null}
     *                    if not applicable.
     */
    private OIDCScopeValue(String value,
                           Scope.Value.Requirement requirement,
                           String[] claims) {

        super(value, requirement);

        if (claims != null) {
            this.claims = Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(claims)));
        } else {
            this.claims = null;
        }
    }


    /**
     * Creates a new OpenID Connect scope value. The requirement is set to
     * {@link OIDCScopeValue.Requirement#OPTIONAL optional}.
     *
     * @param value  The scope value. Must not be {@code null}.
     * @param claims The names of the associated claims. Must not be
     *               {@code null}.
     */
    private OIDCScopeValue(String value,
                           String[] claims) {

        this(value, Scope.Value.Requirement.OPTIONAL, claims);
    }


    /**
     * Returns the names of the associated claims.
     *
     * @return The names of the associated claims, {@code null} if not
     * applicable.
     */
    public Set<String> getClaimNames() {

        return claims;
    }


    /**
     * Gets the claims request JSON object for this OpenID Connect scope
     * value.
     *
     * <p>See OpenID Connect Core 1.0, section 5.1.
     *
     * <p>Example JSON object for "openid" scope value:
     *
     * <pre>
     * {
     *   "sub" : { "essential" : true }
     * }
     * </pre>
     *
     * <p>Example JSON object for "email" scope value:
     *
     * <pre>
     * {
     *   "email"          : null,
     *   "email_verified" : null
     * }
     * </pre>
     *
     * @return The claims request JSON object, {@code null} if not
     * applicable.
     */
    public JsonObject toClaimsRequestJSONObject() {

        JsonObjectBuilder req = Json.createObjectBuilder();

        if (claims == null) {
            return null;
        }

        for (String claim : claims) {

            if (getRequirement() == Scope.Value.Requirement.REQUIRED) {

                // Essential (applies to OPENID - sub only)
                JsonObjectBuilder details = Json.createObjectBuilder();

                details.add("essential", true);
                req.add(claim, details);

            } else {
                // Voluntary
                req.addNull(claim);
            }
        }

        return req.build();
    }


    /**
     * Gets the claims request entries for this OpenID Connect scope value.
     *
     * <p>See OpenID Connect Core 1.0, section 5.1.
     *
     * @return The claims request entries, {@code null} if not applicable
     * (for scope values {@link #OPENID} and
     * {@link #OFFLINE_ACCESS}).
     */
    public Set<ClaimsRequest.Entry> toClaimsRequestEntries() {

        Set<ClaimsRequest.Entry> entries = new HashSet<>();

        if (this == OPENID || this == OFFLINE_ACCESS) {
            return Collections.unmodifiableSet(entries);
        }

        for (String claimName : getClaimNames()) {
            entries.add(new ClaimsRequest.Entry(claimName, ClaimRequirement.VOLUNTARY));
        }

        return Collections.unmodifiableSet(entries);
    }
}