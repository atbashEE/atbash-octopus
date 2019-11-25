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
import java.util.Set;


/**
 * The base abstract class for aggregated and distributed OpenID claims.
 */
abstract class ExternalClaims {


    /**
     * Identifier for the claims source.
     */
    private final String sourceID;


    /**
     * The claim names.
     */
    private final Set<String> names;


    /**
     * Creates a new external OpenID claims instance.
     *
     * @param sourceID Identifier for the claims source. Must not be
     *                 {@code null} or empty string.
     * @param names    The claim names. Must not be {@code null} or empty.
     */
    protected ExternalClaims(final String sourceID, final Set<String> names) {

        if (sourceID == null || sourceID.trim().isEmpty()) {
            throw new IllegalArgumentException("The claims source identifier must not be null or empty");
        }

        this.sourceID = sourceID;

        if (names == null || names.isEmpty()) {
            throw new IllegalArgumentException("The claim names must not be null or empty");
        }

        this.names = names;
    }


    /**
     * Returns the identifier for this claims source.
     *
     * @return The source identifier.
     */
    public String getSourceID() {

        return sourceID;
    }


    /**
     * Returns the claim names.
     *
     * @return The claim names.
     */
    public Set<String> getNames() {

        return names;
    }


    /**
     * Merges this external claims instance into the specified JSON object.
     *
     * @param jsonObject The JSON object. Must not be {@code null}.
     */
    abstract JsonObject mergeInto(JsonObject jsonObject);
}
