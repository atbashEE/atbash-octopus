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


import be.atbash.ee.security.octopus.nimbus.jwt.JWT;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.util.Set;
import java.util.UUID;


/**
 * Aggregated OpenID claims set.
 *
 * <p>Example aggregated claims (included in a UserInfo response):
 *
 * <pre>
 * {
 *   "_claim_names"   : { "address"      : "src1",
 *                        "phone_number" : "src1" },
 *   "_claim_sources" : { "src1" : { "JWT" : "jwt_header.jwt_part2.jwt_part3" } }
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, sections 5.1 and 5.6.2.
 * </ul>
 */
public class AggregatedClaims extends ExternalClaims {


    /**
     * The claims JWT.
     */
    private final JWT claimsJWT;


    /**
     * Creates a new aggregated OpenID claims instance, the claims source
     * identifier is set to a GUUID string.
     *
     * @param names     The claim names. Must not be {@code null} or empty.
     * @param claimsJWT The claims JWT. Must not be {@code null}.
     */
    public AggregatedClaims(final Set<String> names, final JWT claimsJWT) {

        this(UUID.randomUUID().toString(), names, claimsJWT);
    }


    /**
     * Creates a new aggregated OpenID claims instance.
     *
     * @param sourceID  Identifier for the claims source. Must not be
     *                  {@code null} or empty string.
     * @param names     The claim names. Must not be {@code null} or empty.
     * @param claimsJWT The claims JWT. Must not be {@code null}.
     */
    public AggregatedClaims(final String sourceID, final Set<String> names, final JWT claimsJWT) {

        super(sourceID, names);

        if (claimsJWT == null) {
            throw new IllegalArgumentException("The claims JWT must not be null");
        }
        this.claimsJWT = claimsJWT;
    }


    /**
     * Returns the claims JWT.
     *
     * @return The claims JWT.
     */
    public JWT getClaimsJWT() {

        return claimsJWT;
    }


    @Override
    JsonObject mergeInto(final JsonObject jsonObject) {

        JsonObjectBuilder result = Json.createObjectBuilder(jsonObject);

        JsonObjectBuilder claimNamesObject = Json.createObjectBuilder();

        for (String name : getNames()) {
            claimNamesObject.add(name, getSourceID());
        }

        if (jsonObject != null) {
            if (jsonObject.containsKey("_claim_names")) {
                JsonObjectBuilder tempBuilder = Json.createObjectBuilder((JsonObject) jsonObject.get("_claim_names"));
                tempBuilder.addAll(claimNamesObject);
                result.add("_claim_names", tempBuilder.build());
            } else {
                result.add("_claim_names", claimNamesObject.build());
            }
        }


        JsonObjectBuilder sourceSpec = Json.createObjectBuilder();
        sourceSpec.add("JWT", getClaimsJWT().serialize());

        JsonObjectBuilder claimSourcesObject = Json.createObjectBuilder();

        claimSourcesObject.add(getSourceID(), sourceSpec);

        if (jsonObject != null) {
            if (jsonObject.containsKey("_claim_sources")) {
                JsonObjectBuilder tempBuilder = Json.createObjectBuilder((JsonObject) jsonObject.get("_claim_sources"));
                tempBuilder.addAll(claimSourcesObject);
                result.add("_claim_sources", tempBuilder.build());
            } else {
                result.add("_claim_sources", claimSourcesObject.build());
            }
        }
        return result.build();
    }
}
