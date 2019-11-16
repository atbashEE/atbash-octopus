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


import be.atbash.ee.langtag.LangTag;
import be.atbash.ee.langtag.LangTagUtils;
import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.util.DateUtils;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * Claims set serialisable to a JSON object.
 */
public abstract class ClaimsSet {


    /**
     * The JSON object Builder. Null when claims are
     */
    private JsonObjectBuilder claimsBuilder;

    protected JsonObject claims;

    /**
     * Creates a new empty claims set.
     */
    protected ClaimsSet() {

        claimsBuilder = Json.createObjectBuilder();
    }


    /**
     * Creates a new claims set from the specified JSON object.
     *
     * @param jsonObject The JSON object. Must not be {@code null}.
     */
    protected ClaimsSet(JsonObject jsonObject) {

        this();

        if (jsonObject == null) {
            throw new IllegalArgumentException("The JSON object must not be null");
        }


        for (Map.Entry<String, JsonValue> entry : jsonObject.entrySet()) {
            claimsBuilder.add(entry.getKey(), entry.getValue());
        }
    }


    /**
     * Puts all claims from the specified other claims set.
     *
     * @param other The other claims set. Must not be {@code null}.
     */
    public void putAll(ClaimsSet other) {
        validateBuildMode();
        for (Map.Entry<String, JsonValue> entry : other.claimsBuilder.build().entrySet()) {
            claimsBuilder.add(entry.getKey(), entry.getValue());
        }


    }

    private void validateBuildMode() {
        if (claimsBuilder == null) {
            throw new IllegalStateException("ClaimSet is in read mode and can't be changed anymore");
        }
    }


    /**
     * Puts all claims from the specified map.
     *
     * @param claims The claims to put. Must not be {@code null}.
     */
    public void putAll(Map<String, Object> claims) {
        validateBuildMode();
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            JSONObjectUtils.addValue(this.claimsBuilder, entry.getKey(), entry.getValue());
        }

    }


    /**
     * Gets a claim.
     *
     * @param name The claim name. Must not be {@code null}.
     * @return The claim value, {@code null} if not specified.
     */
    public Object getClaim(String name) {
        ensureReadMode();
        return JSONObjectUtils.getJsonValueAsObject(claims.get(name));
    }

    private void ensureReadMode() {
        if (claimsBuilder != null) {
            claims = claimsBuilder.build();
            claimsBuilder = null;
        }
    }


    /*
     * Gets a claim that casts to the specified class.
     *
     * @param name  The claim name. Must not be {@code null}.
     * @param clazz The Java class that the claim value should cast to.
     *              Must not be {@code null}.
     * @return The claim value, {@code null} if not specified or casting
     * failed.

    public <T> T getClaim(final String name, final Class<T> clazz) {

        try {
            return JSONObjectUtils.getGeneric(claimsBuilder, name, clazz);
        } catch (OAuth2ParseException e) {
            return null;
        }
    }

     */


    /**
     * Returns a map of all instances, including language-tagged, of a
     * claim with the specified base name.
     *
     * <p>Example JSON serialised claims set:
     *
     * <pre>
     * {
     *   "month"    : "January",
     *   "month#de" : "Januar"
     *   "month#es" : "enero",
     *   "month#it" : "gennaio"
     * }
     * </pre>
     *
     * <p>The "month" claim instances as java.util.Map:
     *
     * <pre>
     * null = "January" (no language tag)
     * "de" = "Januar"
     * "es" = "enero"
     * "it" = "gennaio"
     * </pre>
     *
     * @param name  The claim name. Must not be {@code null}.
     * @param clazz The Java class that the claim values should cast to.
     *              Must not be {@code null}.
     * @return The matching language-tagged claim values, empty map if
     * none. A {@code null} key indicates the value has no language
     * tag (corresponds to the base name).
     */
    public <T> Map<LangTag, T> getLangTaggedClaim(final String name, final Class<T> clazz) {

        Map<LangTag, Object> matches = LangTagUtils.find(name, claims);
        Map<LangTag, T> out = new HashMap<>();

        for (Map.Entry<LangTag, Object> entry : matches.entrySet()) {

            LangTag langTag = entry.getKey();
            String compositeKey = name + (langTag != null ? "#" + langTag : "");

            /*
            try {
                out.put(langTag, JSONObjectUtils.getGeneric(claimsBuilder, compositeKey, clazz));
            } catch (OAuth2ParseException e) {
                // skip
            }

             */
            throw new IllegalArgumentException("Not converted yet");
        }

        return out;
    }


    /**
     * Sets a claim.
     *
     * @param name  The claim name, with an optional language tag. Must not
     *              be {@code null}.
     * @param value The claim value. Should serialise to a JSON entity. If
     *              {@code null} any existing claim with the same name will
     *              be removed.
     */
    public void setClaim(final String name, final Object value) {
        validateBuildMode();
        if (value != null) {
            JSONObjectUtils.addValue(claimsBuilder, name, value);
        } else {
            claimsBuilder.remove(name);
        }
    }


    /**
     * Sets a claim with an optional language tag.
     *
     * @param name    The claim name. Must not be {@code null}.
     * @param value   The claim value. Should serialise to a JSON entity.
     *                If {@code null} any existing claim with the same name
     *                and language tag (if any) will be removed.
     * @param langTag The language tag of the claim value, {@code null} if
     *                not tagged.
     */
    public void setClaim(final String name, final JsonValue value, final LangTag langTag) {
        String keyName = langTag != null ? name + "#" + langTag : name;
        setClaim(keyName, value);
    }


    /**
     * Gets a string-based claim.
     *
     * @param name The claim name. Must not be {@code null}.
     * @return The claim value, {@code null} if not specified or casting
     * failed.
     */
    public String getStringClaim(final String name) {
        ensureReadMode();
        return JSONObjectUtils.hasValue(claims, name) ? claims.getString(name) : null;

    }


    /**
     * Gets a string-based claim with an optional language tag.
     *
     * @param name    The claim name. Must not be {@code null}.
     * @param langTag The language tag of the claim value, {@code null} to
     *                get the non-tagged value.
     * @return The claim value, {@code null} if not specified or casting
     * failed.
     */
    public String getStringClaim(final String name, final LangTag langTag) {
        ensureReadMode();
        return langTag == null ? getStringClaim(name) : getStringClaim(name + '#' + langTag);
    }


    /**
     * Gets a boolean-based claim.
     *
     * @param name The claim name. Must not be {@code null}.
     * @return The claim value, {@code null} if not specified or casting
     * failed.
     */
    public Boolean getBooleanClaim(final String name) {
        ensureReadMode();
        return JSONObjectUtils.hasValue(claims, name) ? claims.getBoolean(name) : null;
    }


    /**
     * Gets a number-based claim.
     *
     * @param name The claim name. Must not be {@code null}.
     * @return The claim value, {@code null} if not specified or casting
     * failed.
     */
    public Number getNumberClaim(final String name) {
        ensureReadMode();
        return JSONObjectUtils.hasValue(claims, name) ? claims.getJsonNumber(name).numberValue() : null;
    }


    /**
     * Gets an URL string based claim.
     *
     * @param name The claim name. Must not be {@code null}.
     * @return The claim value, {@code null} if not specified or parsing
     * failed.
     */
    public URL getURLClaim(final String name) {
        ensureReadMode();
        try {
            return new URL(claims.getString(name));
        } catch (MalformedURLException e) {
            return null;
        }
    }


    /**
     * Sets an URL string based claim.
     *
     * @param name  The claim name. Must not be {@code null}.
     * @param value The claim value. If {@code null} any existing claim
     *              with the same name will be removed.
     */
    public void setURLClaim(final String name, final URL value) {
        validateBuildMode();
        if (value != null) {
            setClaim(name, value.toString());
        } else {
            claimsBuilder.remove(name);
        }
    }


    /**
     * Gets an URI string based claim.
     *
     * @param name The claim name. Must not be {@code null}.
     * @return The claim value, {@code null} if not specified or parsing
     * failed.
     */
    public URI getURIClaim(final String name) {
        ensureReadMode();
        try {
            return JSONObjectUtils.getURI(claims, name);
        } catch (java.text.ParseException e) {
            return null;
        }
    }


    /**
     * Sets an URI string based claim.
     *
     * @param name  The claim name. Must not be {@code null}.
     * @param value The claim value. If {@code null} any existing claim
     *              with the same name will be removed.
     */
    public void setURIClaim(final String name, final URI value) {
        validateBuildMode();
        if (value != null) {
            setClaim(name, value.toString());
        } else {
            claimsBuilder.remove(name);
        }
    }


    /**
     * Gets an email string based claim.
     *
     * @param name The claim name. Must not be {@code null}.
     * @return The claim value, {@code null} if not specified or parsing
     * failed.
     */
    @Deprecated
    public InternetAddress getEmailClaim(final String name) {
        ensureReadMode();
        try {
            return InternetAddress.parse(claims.getString(name))[0];
        } catch (AddressException e) {
            return null;
        }
    }


    /**
     * Sets an email string based claim.
     *
     * @param name  The claim name. Must not be {@code null}.
     * @param value The claim value. If {@code null} any existing claim
     *              with the same name will be removed.
     */
    @Deprecated
    public void setEmailClaim(final String name, final InternetAddress value) {
        validateBuildMode();
        if (value != null) {
            setClaim(name, value.getAddress());
        } else {
            claimsBuilder.remove(name);
        }
    }


    /**
     * Gets a date / time based claim, represented as the number of seconds
     * from 1970-01-01T0:0:0Z as measured in UTC until the date / time.
     *
     * @param name The claim name. Must not be {@code null}.
     * @return The claim value, {@code null} if not specified or parsing
     * failed.
     */
    public Date getDateClaim(final String name) {
        ensureReadMode();
        try {
            return DateUtils.fromSecondsSinceEpoch(claims.getJsonNumber(name).longValue());
        } catch (Exception e) {
            return null;
        }
    }


    /**
     * Sets a date / time based claim, represented as the number of seconds
     * from 1970-01-01T0:0:0Z as measured in UTC until the date / time.
     *
     * @param name  The claim name. Must not be {@code null}.
     * @param value The claim value. If {@code null} any existing claim
     *              with the same name will be removed.
     */
    public void setDateClaim(final String name, final Date value) {
        validateBuildMode();
        if (value != null) {
            setClaim(name, DateUtils.toSecondsSinceEpoch(value));
        } else {
            claimsBuilder.remove(name);
        }
    }


    /**
     * Gets a string list based claim.
     *
     * @param name The claim name. Must not be {@code null}.
     * @return The claim value, {@code null} if not specified or parsing
     * failed.
     */
    public List<String> getStringListClaim(final String name) {
        ensureReadMode();
        return JSONObjectUtils.getStringList(claims, name);

    }


    /**
     * Gets the JSON object representation of this claims set.
     *
     * <p>Example:
     *
     * <pre>
     * {
     *   "country"       : "USA",
     *   "country#en"    : "USA",
     *   "country#de_DE" : "Vereinigte Staaten",
     *   "country#fr_FR" : "Etats Unis"
     * }
     * </pre>
     *
     * @return The JSON object representation.
     */
    public JsonObjectBuilder toJSONObject() {
        ensureReadMode();

        return Json.createObjectBuilder(claims);

    }


    /**
     * Gets the JSON Web Token (JWT) claims set for this claim set.
     *
     * @return The JWT claims set.
     * @throws OAuth2JSONParseException If the conversion to a JWT claims set fails.
     */
    public JWTClaimsSet toJWTClaimsSet()
            throws OAuth2JSONParseException {

        ensureReadMode();
        try {
            return JWTClaimsSet.parse(claims);

        } catch (java.text.ParseException e) {

            throw new OAuth2JSONParseException(e.getMessage(), e);
        }
    }
}
