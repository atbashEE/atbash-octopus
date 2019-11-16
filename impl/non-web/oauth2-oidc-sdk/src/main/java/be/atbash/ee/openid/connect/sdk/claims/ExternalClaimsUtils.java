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


import javax.json.JsonObject;
import javax.json.JsonString;
import javax.json.JsonValue;
import java.util.*;


/**
 * Aggregated and distributed claims utilities.
 */
final class ExternalClaimsUtils {


    /**
     * Gets the {@code _claim_sources} JSON objects from the specified
     * claims set JSON object.
     *
     * @param claims The claims set JSON object. May be {@code null}.
     * @return The {@code _claims_sources} JSON objects, keyed by source
     * ID, {@code null} if none.
     */
    static Map<String, JsonObject> getExternalClaimSources(final JsonObject claims) {

        Object o = claims.get("_claim_sources");

        if (!(o instanceof JsonObject)) {
            return null;
        }

        JsonObject claimSources = (JsonObject) o;

        if (claimSources.isEmpty()) {
            return null;
        }

        Map<String, JsonObject> out = new HashMap<>();

        for (Map.Entry<String, JsonValue> en : claimSources.entrySet()) {

            String sourceID = en.getKey();

            Object v = en.getValue();
            if (!(v instanceof JsonObject)) {
                continue; // invalid source spec, skip
            }

            JsonObject sourceSpec = (JsonObject) v;

            out.put(sourceID, sourceSpec);
        }

        if (out.isEmpty()) {
            return null;
        }

        return out;
    }


    /**
     * Returns the external claim names (aggregated or distributed) for the
     * specified source.
     *
     * @param claims   The claims set JSON object. May be {@code null}.
     * @param sourceID The source ID. May be {@code null}.
     * @return The claim names, empty set if none are found.
     */
    static Set<String> getExternalClaimNamesForSource(final JsonObject claims, final String sourceID) {

        if (claims == null || sourceID == null) {
            return Collections.emptySet();
        }

        Object claimNamesObject = claims.get("_claim_names");

        if (!(claimNamesObject instanceof JsonObject)) {
            return Collections.emptySet();
        }

        JsonObject claimNamesJSONObject = (JsonObject) claimNamesObject;

        Set<String> claimNames = new HashSet<>();

        for (Map.Entry<String, JsonValue> en : claimNamesJSONObject.entrySet()) {

            JsonValue value = en.getValue();
            if (value.getValueType() == JsonValue.ValueType.STRING && sourceID.equals(((JsonString) (value)).getString())) {
                claimNames.add(en.getKey());
            }
        }

        return claimNames;
    }


    /**
     * Prevents public instantiation.
     */
    private ExternalClaimsUtils() {
    }
}
