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


import be.atbash.ee.oauth2.sdk.ResponseType;
import be.atbash.ee.oauth2.sdk.Scope;
import be.atbash.ee.openid.connect.sdk.claims.ClaimRequirement;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;
import java.text.ParseException;
import java.util.*;


/**
 * Specifies the individual claims to return from the UserInfo endpoint and /
 * or in the ID Token.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 5.5.
 * </ul>
 */
public class ClaimsRequest {


    /**
     * Individual claim request.
     *
     * <p>Related specifications:
     *
     * <ul>
     *     <li>OpenID Connect Core 1.0, section 5.5.1.
     * </ul>
     */
    public static class Entry {


        /**
         * The claim name.
         */
        private final String claimName;


        /**
         * The claim requirement.
         */
        private final ClaimRequirement requirement;


        /**
         * Optional claim value.
         */
        private final String value;


        /**
         * Optional claim values.
         */
        private final List<String> values;


        /**
         * Optional additional claim information.
         *
         * <p>Example additional information in the "info" member:
         *
         * <pre>
         * {
         *   "userinfo" : {
         *       "email": null,
         *       "email_verified": null,
         *       "http://example.info/claims/groups" : { "info" : "custom information" } }
         * }
         * </pre>
         */
        private final Map<String, Object> additionalInformation;


        /**
         * Creates a new individual claim request. The claim
         * requirement is set to voluntary (the default) and no
         * expected value(s) are specified.
         *
         * @param claimName The claim name. Must not be {@code null}.
         */
        public Entry(String claimName) {

            this(claimName, ClaimRequirement.VOLUNTARY, null, null);
        }


        /**
         * Creates a new individual claim request.
         *
         * @param claimName   The claim name. Must not be {@code null}.
         * @param requirement The claim requirement. Must not be
         *                    {@code null}.
         */
        public Entry(String claimName, ClaimRequirement requirement) {

            this(claimName, requirement, null, null, null);
        }


        /**
         * Creates a new individual claim request.
         *
         * @param claimName   The claim name. Must not be {@code null}.
         * @param requirement The claim requirement. Must not be
         *                    {@code null}.
         * @param value       Optional expected value for the claim.
         */
        public Entry(String claimName, ClaimRequirement requirement,
                     String value) {

            this(claimName, requirement, value, null);
        }


        /**
         * Creates a new individual claim request.
         *
         * @param claimName   The claim name. Must not be {@code null}.
         * @param requirement The claim requirement. Must not be
         *                    {@code null}.
         * @param values      Optional expected values for the claim.
         */
        public Entry(String claimName, ClaimRequirement requirement,
                     List<String> values) {

            this(claimName, requirement, null, values, null);
        }


        /**
         * Creates a new individual claim request. This constructor is
         * to be used privately. Ensures that {@code value} and
         * {@code values} are not simultaneously specified.
         *
         * @param claimName   The claim name. Must not be {@code null}.
         * @param requirement The claim requirement. Must not be
         *                    {@code null}.
         * @param value       Optional expected value for the claim. If
         *                    set, then the {@code values} parameter
         *                    must not be set.
         * @param values      Optional expected values for the claim.
         *                    If set, then the {@code value} parameter
         *                    must not be set.
         */
        private Entry(String claimName, ClaimRequirement requirement,
                      String value, List<String> values) {
            this(claimName, requirement, value, values, null);
        }


        /**
         * Creates a new individual claim request. This constructor is
         * to be used privately. Ensures that {@code value} and
         * {@code values} are not simultaneously specified.
         *
         * @param claimName             The claim name. Must not be
         *                              {@code null}.
         * @param requirement           The claim requirement. Must not
         *                              be {@code null}.
         * @param value                 Optional expected value for the
         *                              claim. If set, then the {@code
         *                              values} parameter must not be
         *                              set.
         * @param values                Optional expected values for
         *                              the claim. If set, then the
         *                              {@code value} parameter must
         *                              not be set.
         * @param additionalInformation Optional additional information
         *                              about the requested Claims.
         */
        private Entry(String claimName, ClaimRequirement requirement,
                      String value, List<String> values, Map<String, Object> additionalInformation) {

            if (claimName == null) {
                throw new IllegalArgumentException("The claim name must not be null");
            }

            this.claimName = claimName;


            if (requirement == null) {
                throw new IllegalArgumentException("The claim requirement must not be null");
            }

            this.requirement = requirement;


            if (value != null && values == null) {

                this.value = value;
                this.values = null;

            } else if (value == null && values != null) {

                this.value = null;
                this.values = values;

            } else if (value == null) {

                this.value = null;
                this.values = null;

            } else {

                throw new IllegalArgumentException("Either value or values must be specified, but not both");
            }

            this.additionalInformation = additionalInformation;
        }


        /**
         * Gets the claim name.
         *
         * @return The claim name.
         */
        public String getClaimName() {

            return claimName;
        }


        /**
         * Gets the claim requirement.
         *
         * @return The claim requirement.
         */
        public ClaimRequirement getClaimRequirement() {

            return requirement;
        }

        /**
         * Gets the optional value for the claim.
         *
         * @return The value, {@code null} if not specified.
         */
        public String getValue() {

            return value;
        }


        /**
         * Gets the optional values for the claim.
         *
         * @return The values, {@code null} if not specified.
         */
        public List<String> getValues() {

            return values;
        }


        /**
         * Gets the optional additional information for the claim.
         *
         * <p>Example additional information in the "info" member:
         *
         * <pre>
         * {
         *   "userinfo" : {
         *       "email": null,
         *       "email_verified": null,
         *       "http://example.info/claims/groups" : { "info" : "custom information" } }
         * }
         * </pre>
         *
         * @return The additional information, {@code null} if not
         * specified.
         */
        public Map<String, Object> getAdditionalInformation() {
            return additionalInformation;
        }


        /**
         * Returns the JSON object representation of the specified
         * collection of individual claim requests.
         *
         * <p>Example:
         *
         * <pre>
         * {
         *   "given_name": {"essential": true},
         *   "nickname": null,
         *   "email": {"essential": true},
         *   "email_verified": {"essential": true},
         *   "picture": null,
         *   "http://example.info/claims/groups": null
         * }
         * </pre>
         *
         * @param entries The entries to serialise. Must not be
         *                {@code null}.
         * @return The corresponding JSON object, empty if no claims
         * were found.
         */
        public static JsonObject toJSONObject(Collection<Entry> entries) {

            JsonObjectBuilder result = Json.createObjectBuilder();


            for (Entry entry : entries) {

                // Compose the optional value
                JsonObjectBuilder entrySpec = null;

                if (entry.getValue() != null) {

                    entrySpec = Json.createObjectBuilder();
                    entrySpec.add("value", entry.getValue());
                }

                if (entry.getValues() != null) {

                    // Either "value" or "values", or none
                    // may be defined
                    entrySpec = Json.createObjectBuilder();
                    entrySpec.add("values", JSONObjectUtils.asJsonArray(entry.getValues()));
                }

                if (entry.getClaimRequirement().equals(ClaimRequirement.ESSENTIAL)) {

                    if (entrySpec == null) {
                        entrySpec = Json.createObjectBuilder();
                    }
                    entrySpec.add("essential", true);
                }

                if (entry.getAdditionalInformation() != null) {
                    if (entrySpec == null) {
                        entrySpec = Json.createObjectBuilder();
                    }
                    for (Map.Entry<String, Object> additionalInformationEntry : entry.getAdditionalInformation().entrySet()) {
                        JSONObjectUtils.addValue(entrySpec, additionalInformationEntry.getKey(), additionalInformationEntry.getValue());
                    }
                }

                String claimName = entry.getClaimName();
                if (entrySpec == null) {
                    result.addNull(claimName);
                } else {
                    result.add(claimName, entrySpec.build());
                }
            }

            return result.build();
        }


        /**
         * Parses a collection of individual claim requests from the
         * specified JSON object. Request entries that are not
         * understood are silently ignored.
         *
         * @param jsonObject The JSON object to parse. Must not be
         *                   {@code null}.
         * @return The collection of claim requests.
         */
        public static Collection<Entry> parseEntries(JsonObject jsonObject) {

            Collection<Entry> entries = new LinkedList<>();

            if (jsonObject.isEmpty()) {
                return entries;
            }

            for (Map.Entry<String, JsonValue> member : jsonObject.entrySet()) {

                // Process the key
                String claimName = member.getKey();

                // Parse the optional value
                if (member.getValue() == null) {

                    // Voluntary claim with no value(s)
                    entries.add(new Entry(claimName));
                    continue;
                }

                try {

                    JsonObject entrySpec;
                    if (member.getValue().getValueType() == JsonValue.ValueType.NULL) {
                        entrySpec = Json.createObjectBuilder().build();
                    } else {
                        entrySpec = (JsonObject) member.getValue();
                    }

                    ClaimRequirement requirement = ClaimRequirement.VOLUNTARY;

                    if (entrySpec.containsKey("essential")) {

                        boolean isEssential = entrySpec.getBoolean("essential");

                        if (isEssential) {
                            requirement = ClaimRequirement.ESSENTIAL;
                        }
                    }

                    if (entrySpec.containsKey("value")) {

                        String expectedValue = entrySpec.getString("value");
                        Map<String, Object> additionalInformation = getAdditionalInformationFromClaim(entrySpec);
                        entries.add(new Entry(claimName, requirement, expectedValue, null, additionalInformation));

                    } else if (entrySpec.containsKey("values")) {

                        List<String> expectedValues = new LinkedList<>(JSONObjectUtils.getStringList(entrySpec, "values"));
                        Map<String, Object> additionalInformation = getAdditionalInformationFromClaim(entrySpec);

                        entries.add(new Entry(claimName, requirement, null, expectedValues, additionalInformation));

                    } else {
                        Map<String, Object> additionalInformation = getAdditionalInformationFromClaim(entrySpec);
                        entries.add(new Entry(claimName, requirement, null, null, additionalInformation));
                    }

                } catch (Exception e) {
                    // Ignore and continue
                }
            }

            return entries;
        }


        private static Map<String, Object> getAdditionalInformationFromClaim(JsonObject entrySpec) {
            List<String> keysToRemove = Arrays.asList("essential", "value", "values");
            HashSet<String> keys = new HashSet<>(entrySpec.keySet());
            keys.removeAll(keysToRemove);
            Map<String, Object> additionalClaimInformation = new HashMap<>();
            for (String key : keys) {

                additionalClaimInformation.put(key, JSONObjectUtils.getJsonValueAsObject(entrySpec.get(key)));

            }
            return additionalClaimInformation.isEmpty() ? null : additionalClaimInformation;
        }
    }


    /**
     * The requested ID token claims, keyed by claim name and language tag.
     */
    private final Map<String, Entry> idTokenClaims = new HashMap<>();


    /**
     * The requested UserInfo claims, keyed by claim name and language tag.
     */
    private final Map<String, Entry> userInfoClaims = new HashMap<>();


    /**
     * Creates a new empty claims request.
     */
    public ClaimsRequest() {

        // Nothing to initialise
    }


    /**
     * Adds the entries from the specified other claims request.
     *
     * @param other The other claims request. If {@code null} no claims
     *              request entries will be added to this claims request.
     */
    public void add(ClaimsRequest other) {

        if (other == null) {
            return;
        }

        idTokenClaims.putAll(other.idTokenClaims);
        userInfoClaims.putAll(other.userInfoClaims);
    }


    /**
     * Adds the specified ID token claim to the request. It is marked as
     * voluntary and no language tag and value(s) are associated with it.
     *
     * @param claimName The claim name. Must not be {@code null}.
     */
    public void addIDTokenClaim(String claimName) {

        addIDTokenClaim(claimName, ClaimRequirement.VOLUNTARY);
    }


    /**
     * Adds the specified ID token claim to the request. No language tag
     * and value(s) are associated with it.
     *
     * @param claimName   The claim name. Must not be {@code null}.
     * @param requirement The claim requirement. Must not be {@code null}.
     */
    public void addIDTokenClaim(String claimName, ClaimRequirement requirement) {


        addIDTokenClaim(claimName, requirement, (String) null);
    }


    /**
     * Adds the specified ID token claim to the request.
     *
     * @param claimName   The claim name. Must not be {@code null}.
     * @param requirement The claim requirement. Must not be {@code null}.
     * @param value       The expected claim value, {@code null} if not
     *                    specified.
     */
    public void addIDTokenClaim(String claimName, ClaimRequirement requirement, String value) {

        addIDTokenClaim(new Entry(claimName, requirement, value));
    }


    /**
     * Adds the specified ID token claim to the request.
     *
     * @param claimName             The claim name. Must not be
     *                              {@code null}.
     * @param requirement           The claim requirement. Must not be
     *                              {@code null}.
     * @param value                 The expected claim value, {@code null}
     *                              if not specified.
     * @param additionalInformation The additional information for this
     *                              claim, {@code null} if not specified.
     */
    public void addIDTokenClaim(String claimName, ClaimRequirement requirement,
                                String value, Map<String, Object> additionalInformation) {

        addIDTokenClaim(new Entry(claimName, requirement, value, null, additionalInformation));
    }


    /**
     * Adds the specified ID token claim to the request.
     *
     * @param claimName   The claim name. Must not be {@code null}.
     * @param requirement The claim requirement. Must not be {@code null}.
     * @param values      The expected claim values, {@code null} if not
     *                    specified.
     */
    public void addIDTokenClaim(String claimName, ClaimRequirement requirement,
                                List<String> values) {

        addIDTokenClaim(new Entry(claimName, requirement, values));
    }


    /**
     * Adds the specified ID token claim to the request.
     *
     * @param claimName             The claim name. Must not be
     *                              {@code null}.
     * @param requirement           The claim requirement. Must not be
     *                              {@code null}.
     * @param values                The expected claim values, {@code null}
     *                              if not specified.
     * @param additionalInformation The additional information for this
     *                              claim, {@code null} if not specified.
     */
    public void addIDTokenClaim(String claimName, ClaimRequirement requirement,
                                List<String> values, Map<String, Object> additionalInformation) {

        addIDTokenClaim(new Entry(claimName, requirement, null, values, additionalInformation));
    }


    /**
     * Adds the specified ID token claim to the request.
     *
     * @param entry The individual ID token claim request. Must not be
     *              {@code null}.
     */
    public void addIDTokenClaim(Entry entry) {

        idTokenClaims.put(entry.getClaimName(), entry);
    }


    /**
     * Gets the requested ID token claims.
     *
     * @return The ID token claims, as an unmodifiable collection, empty
     * set if none.
     */
    public Collection<Entry> getIDTokenClaims() {

        return Collections.unmodifiableCollection(idTokenClaims.values());
    }


    /**
     * Gets the names of the requested ID token claim names.
     *
     * @return The ID token claim names, as an unmodifiable set, empty set
     * if none.
     */
    public Set<String> getIDTokenClaimNames() {

        Set<String> names = new HashSet<>();

        for (Entry en : idTokenClaims.values()) {
            names.add(en.getClaimName());
        }

        return Collections.unmodifiableSet(names);
    }


    /**
     * Removes the specified ID token claim from the request.
     *
     * @param claimName The claim name. Must not be {@code null}.
     * @return The removed ID token claim, {@code null} if not found.
     */
    public Entry removeIDTokenClaim(String claimName) {

        return idTokenClaims.remove(claimName);
    }


    /**
     * Removes the specified ID token claims from the request, in all
     * existing language tag variations.
     *
     * @param claimName The claim name. Must not be {@code null}.
     * @return The removed ID token claims, as an unmodifiable collection,
     * empty set if none were found.
     */
    public Collection<Entry> removeIDTokenClaims(String claimName) {

        Collection<Entry> removedClaims = new LinkedList<>();

        Iterator<Map.Entry<String, Entry>> it = idTokenClaims.entrySet().iterator();

        while (it.hasNext()) {

            Map.Entry<String, Entry> reqEntry = it.next();

            if (reqEntry.getKey().equals(claimName)) {

                removedClaims.add(reqEntry.getValue());

                it.remove();
            }
        }

        return Collections.unmodifiableCollection(removedClaims);
    }


    /**
     * Adds the specified UserInfo claim to the request. It is marked as
     * voluntary and no language tag and value(s) are associated with it.
     *
     * @param claimName The claim name. Must not be {@code null}.
     */
    public void addUserInfoClaim(String claimName) {

        addUserInfoClaim(claimName, ClaimRequirement.VOLUNTARY);
    }


    /**
     * Adds the specified UserInfo claim to the request. No language tag and
     * value(s) are associated with it.
     *
     * @param claimName   The claim name. Must not be {@code null}.
     * @param requirement The claim requirement. Must not be {@code null}.
     */
    public void addUserInfoClaim(String claimName, ClaimRequirement requirement) {

        addUserInfoClaim(claimName, requirement, (String) null);
    }

    /**
     * Adds the specified UserInfo claim to the request.
     *
     * @param claimName   The claim name. Must not be {@code null}.
     * @param requirement The claim requirement. Must not be {@code null}.
     * @param value       The expected claim value, {@code null} if not
     *                    specified.
     */
    public void addUserInfoClaim(String claimName, ClaimRequirement requirement,
                                 String value) {

        addUserInfoClaim(new Entry(claimName, requirement, value));
    }


    /**
     * Adds the specified UserInfo claim to the request.
     *
     * @param claimName             The claim name. Must not be {@code
     *                              null}.
     * @param requirement           The claim requirement. Must not be
     *                              {@code null}.
     * @param value                 The expected claim value, {@code null}
     *                              if not specified.
     * @param additionalInformation The additional information for this
     *                              claim, {@code null} if not specified.
     */
    public void addUserInfoClaim(String claimName, ClaimRequirement requirement,
                                 String value, Map<String, Object> additionalInformation) {

        addUserInfoClaim(new Entry(claimName, requirement, value, null, additionalInformation));
    }


    /**
     * Adds the specified UserInfo claim to the request.
     *
     * @param claimName   The claim name. Must not be {@code null}.
     * @param requirement The claim requirement. Must not be {@code null}.
     * @param values      The expected claim values, {@code null} if not
     *                    specified.
     */
    public void addUserInfoClaim(String claimName, ClaimRequirement requirement,
                                 List<String> values) {

        addUserInfoClaim(new Entry(claimName, requirement, values));
    }


    /**
     * Adds the specified UserInfo claim to the request.
     *
     * @param claimName             The claim name. Must not be
     *                              {@code null}.
     * @param requirement           The claim requirement. Must not be
     *                              {@code null}.
     * @param values                The expected claim values, {@code null}
     *                              if not specified.
     * @param additionalInformation The additional information for this
     *                              claim, {@code null} if not specified.
     */
    public void addUserInfoClaim(String claimName, ClaimRequirement requirement,
                                 List<String> values, Map<String, Object> additionalInformation) {

        addUserInfoClaim(new Entry(claimName, requirement, null, values, additionalInformation));
    }


    /**
     * Adds the specified UserInfo claim to the request.
     *
     * @param entry The individual UserInfo claim request. Must not be
     *              {@code null}.
     */
    public void addUserInfoClaim(Entry entry) {

        userInfoClaims.put(entry.getClaimName(), entry);
    }


    /**
     * Gets the requested UserInfo claims.
     *
     * @return The UserInfo claims, as an unmodifiable collection, empty
     * set if none.
     */
    public Collection<Entry> getUserInfoClaims() {

        return Collections.unmodifiableCollection(userInfoClaims.values());
    }


    /**
     * Gets the names of the requested UserInfo claim names.
     *
     * @return The UserInfo claim names, as an unmodifiable set, empty set
     * if none.
     */
    public Set<String> getUserInfoClaimNames() {

        Set<String> names = new HashSet<>();

        for (Entry en : userInfoClaims.values()) {
            names.add(en.getClaimName());
        }

        return Collections.unmodifiableSet(names);
    }


    /**
     * Removes the specified UserInfo claim from the request.
     *
     * @param claimName The claim name. Must not be {@code null}.

     * @return The removed UserInfo claim, {@code null} if not found.
     */
    public Entry removeUserInfoClaim(String claimName) {


        return userInfoClaims.remove(claimName);
    }


    /**
     * Removes the specified UserInfo claims from the request, in all
     * existing language tag variations.
     *
     * @param claimName The claim name. Must not be {@code null}.
     * @return The removed UserInfo claims, as an unmodifiable collection,
     * empty set if none were found.
     */
    public Collection<Entry> removeUserInfoClaims(String claimName) {

        Collection<Entry> removedClaims = new LinkedList<>();

        Iterator<Map.Entry<String, Entry>> it = userInfoClaims.entrySet().iterator();

        while (it.hasNext()) {

            Map.Entry<String, Entry> reqEntry = it.next();

            if (reqEntry.getKey().equals(claimName)) {

                removedClaims.add(reqEntry.getValue());

                it.remove();
            }
        }

        return Collections.unmodifiableCollection(removedClaims);
    }


    /**
     * Returns the JSON object representation of this claims request.
     *
     * <p>Example:
     *
     * <pre>
     * {
     *   "userinfo":
     *    {
     *     "given_name": {"essential": true},
     *     "nickname": null,
     *     "email": {"essential": true},
     *     "email_verified": {"essential": true},
     *     "picture": null,
     *     "http://example.info/claims/groups": null
     *    },
     *   "id_token":
     *    {
     *     "auth_time": {"essential": true},
     *     "acr": {"values": ["urn:mace:incommon:iap:silver"] }
     *    }
     * }
     * </pre>
     *
     * @return The corresponding JSON object, empty if no ID token and
     * UserInfo claims are specified.
     */
    public JsonObject toJSONObject() {

        JsonObjectBuilder result = Json.createObjectBuilder();

        Collection<Entry> idTokenEntries = getIDTokenClaims();

        if (!idTokenEntries.isEmpty()) {

            result.add("id_token", Entry.toJSONObject(idTokenEntries));
        }

        Collection<Entry> userInfoEntries = getUserInfoClaims();

        if (!userInfoEntries.isEmpty()) {

            result.add("userinfo", Entry.toJSONObject(userInfoEntries));
        }

        return result.build();
    }


    @Override
    public String toString() {

        return toJSONObject().toString();
    }


    /**
     * Resolves the claims request for the specified response type and
     * scope. The scope values that are {@link OIDCScopeValue standard
     * OpenID scope values} are resolved to their respective individual
     * claims requests, any other scope values are ignored.
     *
     * @param responseType The response type. Must not be {@code null}.
     * @param scope        The scope, {@code null} if not specified (for a
     *                     plain OAuth 2.0 authorisation request with no
     *                     scope explicitly specified).
     * @return The claims request.
     */
    public static ClaimsRequest resolve(ResponseType responseType, Scope scope) {

        return resolve(responseType, scope, Collections.emptyMap());
    }


    /**
     * Resolves the claims request for the specified response type and
     * scope. The scope values that are {@link OIDCScopeValue standard
     * OpenID scope values} are resolved to their respective individual
     * claims requests, any other scope values are checked in the specified
     * custom claims map and resolved accordingly.
     *
     * @param responseType The response type. Must not be {@code null}.
     * @param scope        The scope, {@code null} if not specified (for a
     *                     plain OAuth 2.0 authorisation request with no
     *                     scope explicitly specified).
     * @param customClaims Custom scope value to set of claim names map,
     *                     {@code null} if not specified.
     * @return The claims request.
     */
    public static ClaimsRequest resolve(ResponseType responseType,
                                        Scope scope,
                                        Map<Scope.Value, Set<String>> customClaims) {

        // Determine the claims target (ID token or UserInfo)
        final boolean switchToIDToken =
                responseType.contains(OIDCResponseTypeValue.ID_TOKEN) &&
                        !responseType.contains(ResponseType.Value.CODE) &&
                        !responseType.contains(ResponseType.Value.TOKEN);

        ClaimsRequest claimsRequest = new ClaimsRequest();

        if (scope == null) {
            // Plain OAuth 2.0 mode
            return claimsRequest;
        }

        for (Scope.Value value : scope) {

            Set<Entry> entries;

            if (value.equals(OIDCScopeValue.PROFILE)) {

                entries = OIDCScopeValue.PROFILE.toClaimsRequestEntries();

            } else if (value.equals(OIDCScopeValue.EMAIL)) {

                entries = OIDCScopeValue.EMAIL.toClaimsRequestEntries();

            } else if (value.equals(OIDCScopeValue.PHONE)) {

                entries = OIDCScopeValue.PHONE.toClaimsRequestEntries();

            } else if (value.equals(OIDCScopeValue.ADDRESS)) {

                entries = OIDCScopeValue.ADDRESS.toClaimsRequestEntries();

            } else if (customClaims != null && customClaims.containsKey(value)) {

                // Process custom scope value -> claim names expansion, e.g.
                // "corp_profile" -> ["employeeNumber", "dept", "ext"]
                Set<String> claimNames = customClaims.get(value);

                if (claimNames == null || claimNames.isEmpty()) {
                    continue; // skip
                }

                entries = new HashSet<>();

                for (String claimName : claimNames) {
                    entries.add(new ClaimsRequest.Entry(claimName, ClaimRequirement.VOLUNTARY));
                }

            } else {

                continue; // skip
            }

            for (ClaimsRequest.Entry en : entries) {

                if (switchToIDToken) {
                    claimsRequest.addIDTokenClaim(en);
                } else {
                    claimsRequest.addUserInfoClaim(en);
                }
            }
        }

        return claimsRequest;
    }


    private static Map<String, Object> resolveAdditionalInformationForClaim(Map<String, Object> customClaims) {
        customClaims.remove("essential");
        customClaims.remove("value");
        customClaims.remove("values");
        return customClaims.isEmpty() ? null : customClaims;
    }


    /**
     * Resolves the merged claims request from the specified OpenID
     * authentication request parameters. The scope values that are {@link
     * OIDCScopeValue standard OpenID scope values} are resolved to their
     * respective individual claims requests, any other scope values are
     * ignored.
     *
     * @param responseType  The response type. Must not be {@code null}.
     * @param scope         The scope, {@code null} if not specified (for a
     *                      plain OAuth 2.0 authorisation request with no
     *                      scope explicitly specified).
     * @param claimsRequest The claims request, corresponding to the
     *                      optional {@code claims} OpenID Connect
     *                      authorisation request parameter, {@code null}
     *                      if not specified.
     * @return The merged claims request.
     */
    public static ClaimsRequest resolve(ResponseType responseType,
                                        Scope scope,
                                        ClaimsRequest claimsRequest) {

        return resolve(responseType, scope, claimsRequest, Collections.emptyMap());
    }


    /**
     * Resolves the merged claims request from the specified OpenID
     * authentication request parameters. The scope values that are {@link
     * OIDCScopeValue standard OpenID scope values} are resolved to their
     * respective individual claims requests, any other scope values are
     * checked in the specified custom claims map and resolved accordingly.
     *
     * @param responseType  The response type. Must not be {@code null}.
     * @param scope         The scope, {@code null} if not specified (for a
     *                      plain OAuth 2.0 authorisation request with no
     *                      scope explicitly specified).
     * @param claimsRequest The claims request, corresponding to the
     *                      optional {@code claims} OpenID Connect
     *                      authorisation request parameter, {@code null}
     *                      if not specified.
     * @param customClaims  Custom scope value to set of claim names map,
     *                      {@code null} if not specified.
     * @return The merged claims request.
     */
    public static ClaimsRequest resolve(ResponseType responseType,
                                        Scope scope,
                                        ClaimsRequest claimsRequest,
                                        Map<Scope.Value, Set<String>> customClaims) {

        ClaimsRequest mergedClaimsRequest = resolve(responseType, scope, customClaims);

        mergedClaimsRequest.add(claimsRequest);

        return mergedClaimsRequest;
    }


    /**
     * Resolves the merged claims request for the specified OpenID
     * authentication request. The scope values that are {@link
     * OIDCScopeValue standard OpenID scope values} are resolved to their
     * respective individual claims requests, any other scope values are
     * ignored.
     *
     * @param authRequest The OpenID authentication request. Must not be
     *                    {@code null}.
     * @return The merged claims request.
     */
    public static ClaimsRequest resolve(AuthenticationRequest authRequest) {

        return resolve(authRequest.getResponseType(), authRequest.getScope(), authRequest.getClaims());
    }


    /**
     * Parses a claims request from the specified JSON object
     * representation. Unexpected members in the JSON object are silently
     * ignored.
     *
     * @param jsonObject The JSON object to parse. Must not be
     *                   {@code null}.
     * @return The claims request.
     */
    public static ClaimsRequest parse(JsonObject jsonObject) {

        ClaimsRequest claimsRequest = new ClaimsRequest();

        try {
            if (jsonObject.containsKey("id_token")) {

                JsonObject idTokenObject = jsonObject.getJsonObject("id_token");

                Collection<Entry> idTokenClaims = Entry.parseEntries(idTokenObject);

                for (Entry entry : idTokenClaims) {
                    claimsRequest.addIDTokenClaim(entry);
                }
            }


            if (jsonObject.containsKey("userinfo")) {

                JsonObject userInfoObject = jsonObject.getJsonObject("userinfo");

                Collection<Entry> userInfoClaims = Entry.parseEntries(userInfoObject);

                for (Entry entry : userInfoClaims) {
                    claimsRequest.addUserInfoClaim(entry);
                }
            }

        } catch (Exception e) {

            // Ignore
        }

        return claimsRequest;
    }


    /**
     * Parses a claims request from the specified JSON object string
     * representation. Unexpected members in the JSON object are silently
     * ignored.
     *
     * @param json The JSON object string to parse. Must not be
     *             {@code null}.
     * @return The claims request.
     * @throws ParseException If the string couldn't be parsed to a valid
     *                        JSON object.
     */
    public static ClaimsRequest parse(String json)
            throws ParseException {

        return parse(JSONObjectUtils.parse(json));
    }
}
