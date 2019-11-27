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


import be.atbash.ee.oauth2.sdk.token.AccessToken;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.net.URI;
import java.util.Set;
import java.util.UUID;


/**
 * Distributed OpenID claims set.
 *
 * <p>Example distributed claims with an access token (included in a UserInfo
 * response):
 *
 * <pre>
 * {
 *   "_claim_names"   : { "credit_score" : "src1" },
 *   "_claim_sources" : { "src1" : { "endpoint"     : "https://creditagency.example.com/claims_here",
 *                                   "access_token" : "ksj3n283dke" } }
 * }
 * </pre>
 *
 * <p>Example distributed claims without a specified access token (included in
 * a UserInfo response):
 *
 * <pre>
 * {
 *   "_claim_names" : { "payment_info"     : "src2",
 *                      "shipping_address" : "src2" },
 *   "_claim_sources" : { "src2" : { "endpoint" : "https://bank.example.com/claim_source" } }
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, sections 5.1 and 5.6.2.
 * </ul>
 */
public class DistributedClaims extends ExternalClaims {


    /**
     * The claims source endpoint.
     */
    private final URI sourceEndpoint;


    /**
     * Access token for retrieving the claims at the source URI,
     * {@code null} if not specified.
     */
    private final AccessToken accessToken;


    /**
     * Creates a new aggregated OpenID claims instance, the claims source
     * identifier is set to a GUUID string.
     *
     * @param names          The claim names. Must not be {@code null} or
     *                       empty.
     * @param sourceEndpoint The claims source endpoint. Must not be
     *                       {@code null}.
     * @param accessToken    Access token for retrieving the claims at the
     *                       source endpoint, {@code null} if not
     *                       specified.
     */
    public DistributedClaims(Set<String> names, URI sourceEndpoint, AccessToken accessToken) {

        this(UUID.randomUUID().toString(), names, sourceEndpoint, accessToken);
    }


    /**
     * Creates a new aggregated OpenID claims instance.
     *
     * @param sourceID       Identifier for the claims source. Must not be
     *                       {@code null} or empty string.
     * @param names          The claim names. Must not be {@code null} or
     *                       empty.
     * @param sourceEndpoint The claims source endpoint. Must not be
     *                       {@code null}.
     * @param accessToken    Access token for retrieving the claims at the
     *                       source endpoint, {@code null} if not
     *                       specified.
     */
    public DistributedClaims(String sourceID, Set<String> names, URI sourceEndpoint, AccessToken accessToken) {

        super(sourceID, names);

        if (sourceEndpoint == null) {
            throw new IllegalArgumentException("The claims source URI must not be null");
        }

        this.sourceEndpoint = sourceEndpoint;

        this.accessToken = accessToken;
    }


    /**
     * Returns the claims source endpoint.
     *
     * @return The claims source endpoint.
     */
    public URI getSourceEndpoint() {

        return sourceEndpoint;
    }


    /**
     * Returns the access token for retrieving the claims at the source
     * endpoint.
     *
     * @return The access token for retrieving the claims at the source
     * endpoint, {@code null} if not specified.
     */
    public AccessToken getAccessToken() {

        return accessToken;
    }


    @Override
    JsonObject mergeInto(JsonObject jsonObject) {

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

        sourceSpec.add("endpoint", getSourceEndpoint().toString());
        if (getAccessToken() != null) {
            sourceSpec.add("access_token", getAccessToken().getValue());
        }
        JsonObjectBuilder claimSourcesObject = Json.createObjectBuilder();

        claimSourcesObject.add(getSourceID(), sourceSpec);

        if (jsonObject != null) {
            if (jsonObject.containsKey("_claim_sour ces")) {
                JsonObjectBuilder tempBuilder = Json.createObjectBuilder((JsonObject) jsonObject.get("_claim_sources"));
                tempBuilder.addAll(claimSourcesObject);
                result.add("_claim_names", tempBuilder.build());
            } else {
                result.add("_claim_sources", claimSourcesObject.build());
            }
        }
        return result.build();
    }
}
