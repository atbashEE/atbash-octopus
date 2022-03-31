/*
 * Copyright 2014-2020 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.oauth2.sdk.client;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.ProtectedResourceRequest;
import be.atbash.ee.oauth2.sdk.SerializeException;
import be.atbash.ee.oauth2.sdk.auth.Secret;
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;

import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;


/**
 * Client registration request.
 *
 * <p>Example HTTP request:
 *
 * <pre>
 * PUT /register/s6BhdRkqt3 HTTP/1.1
 * Accept: application/json
 * Host: server.example.com
 * Authorization: Bearer reg-23410913-abewfq.123483
 *
 * {
 *  "client_id"                  :"s6BhdRkqt3",
 *  "client_secret"              : "cf136dc3c1fc93f31185e5885805d",
 *  "redirect_uris"              : [ "https://client.example.org/callback",
 *                                   "https://client.example.org/alt" ],
 *  "scope"                      : "read write dolphin",
 *  "grant_types"                : [ "authorization_code", "refresh_token" ]
 *  "token_endpoint_auth_method" : "client_secret_basic",
 *  "jwks_uri"                   : "https://client.example.org/my_public_keys.jwks"
 *  "client_name"                : "My New Example",
 *  "client_name#fr"             : "Mon Nouvel Exemple",
 *  "logo_uri"                   : "https://client.example.org/newlogo.png"
 *  "logo_uri#fr"                : "https://client.example.org/fr/newlogo.png"
 * }
 *
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Dynamic Client Registration Management Protocol (RFC
 *         7592), section 2.2.
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591), section
 *         2.
 * </ul>
 */
public class ClientUpdateRequest extends ProtectedResourceRequest {


    /**
     * The registered client ID.
     */
    private final ClientID id;


    /**
     * The client metadata.
     */
    private final ClientMetadata metadata;


    /**
     * The optional client secret.
     */
    private final Secret secret;


    /**
     * Creates a new client update request.
     *
     * @param uri         The URI of the client update endpoint. May be
     *                    {@code null} if the {@link #toHTTPRequest()}
     *                    method will not be used.
     * @param id          The client ID. Must not be {@code null}.
     * @param accessToken The client registration access token. Must not be
     *                    {@code null}.
     * @param metadata    The client metadata. Must not be {@code null} and
     *                    must specify one or more redirection URIs.
     * @param secret      The optional client secret, {@code null} if not
     *                    specified.
     */
    public ClientUpdateRequest(URI uri,
                               ClientID id,
                               BearerAccessToken accessToken,
                               ClientMetadata metadata,
                               Secret secret) {

        super(uri, accessToken);

        if (id == null) {
            throw new IllegalArgumentException("The client identifier must not be null");
        }

        this.id = id;

        if (metadata == null) {
            throw new IllegalArgumentException("The client metadata must not be null");
        }

        this.metadata = metadata;

        this.secret = secret;
    }


    /**
     * Gets the client ID. Corresponds to the {@code client_id} client
     * registration parameter.
     *
     * @return The client ID, {@code null} if not specified.
     */
    public ClientID getClientID() {

        return id;
    }


    /**
     * Gets the associated client metadata.
     *
     * @return The client metadata.
     */
    public ClientMetadata getClientMetadata() {

        return metadata;
    }


    /**
     * Gets the client secret. Corresponds to the {@code client_secret}
     * registration parameters.
     *
     * @return The client secret, {@code null} if not specified.
     */
    public Secret getClientSecret() {

        return secret;
    }


    @Override
    public HTTPRequest toHTTPRequest() {

        if (getEndpointURI() == null) {
            throw new SerializeException("The endpoint URI is not specified");
        }

        URL endpointURL;

        try {
            endpointURL = getEndpointURI().toURL();

        } catch (MalformedURLException e) {

            throw new SerializeException(e.getMessage(), e);
        }

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.PUT, endpointURL);

        httpRequest.setAuthorization(getAccessToken().toAuthorizationHeader());

        httpRequest.setContentType(CommonContentTypes.APPLICATION_JSON);

        JsonObjectBuilder jsonObject = metadata.toJSONObject();

        jsonObject.add("client_id", id.getValue());

        if (secret != null) {
            jsonObject.add("client_secret", secret.getValue());
        }

        httpRequest.setQuery(jsonObject.build().toString());

        return httpRequest;
    }


    /**
     * Parses a client update request from the specified HTTP PUT request.
     *
     * @param httpRequest The HTTP request. Must not be {@code null}.
     * @return The client update request.
     * @throws OAuth2JSONParseException If the HTTP request couldn't be parsed to a
     *                                  client update request.
     */
    public static ClientUpdateRequest parse(HTTPRequest httpRequest)
            throws OAuth2JSONParseException {

        httpRequest.ensureMethod(HTTPRequest.Method.PUT);

        BearerAccessToken accessToken = BearerAccessToken.parse(httpRequest.getAuthorization());

        JsonObject jsonObject = httpRequest.getQueryAsJSONObject();

        ClientID id = new ClientID(jsonObject.getString("client_id"));

        ClientMetadata metadata = ClientMetadata.parse(jsonObject);

        Secret clientSecret = null;

        if (jsonObject.get("client_secret") != null) {
            clientSecret = new Secret(jsonObject.getString("client_secret"));
        }

        URI endpointURI;

        try {
            endpointURI = httpRequest.getURL().toURI();

        } catch (URISyntaxException e) {

            throw new OAuth2JSONParseException(e.getMessage(), e);
        }

        return new ClientUpdateRequest(endpointURI, id, accessToken, metadata, clientSecret);
    }
}
