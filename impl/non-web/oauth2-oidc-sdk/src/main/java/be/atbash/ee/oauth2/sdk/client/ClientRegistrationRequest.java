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
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSObject;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import be.atbash.util.StringUtils;

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
 * POST /register HTTP/1.1
 * Content-Type: application/json
 * Accept: application/json
 * Authorization: Bearer ey23f2.adfj230.af32-developer321
 * Host: server.example.com
 *
 * {
 *   "redirect_uris"              : [ "https://client.example.org/callback",
 *                                    "https://client.example.org/callback2" ],
 *   "client_name"                : "My Example Client",
 *   "client_name#ja-Jpan-JP"     : "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D",
 *   "token_endpoint_auth_method" : "client_secret_basic",
 *   "scope"                      : "read write dolphin",
 *   "logo_uri"                   : "https://client.example.org/logo.png",
 *   "jwks_uri"                   : "https://client.example.org/my_public_keys.jwks"
 * }
 * </pre>
 *
 * <p>Example HTTP request with a software statement:
 *
 * <pre>
 * POST /register HTTP/1.1
 * Content-Type: application/json
 * Accept: application/json
 * Host: server.example.com
 *
 * {
 *   "redirect_uris"               : [ "https://client.example.org/callback",
 *                                     "https://client.example.org/callback2" ],
 *   "software_statement"          : "eyJhbGciOiJFUzI1NiJ9.eyJpc3Mi[...omitted for brevity...]",
 *   "scope"                       : "read write",
 *   "example_extension_parameter" : "example_value"
 * }
 *
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591), sections
 *         2 and 3.1.
 * </ul>
 */
public class ClientRegistrationRequest extends ProtectedResourceRequest {


    /**
     * The client metadata.
     */
    private final ClientMetadata metadata;


    /**
     * The optional software statement.
     */
    private final SignedJWT softwareStatement;


    /**
     * Creates a new client registration request.
     *
     * @param uri         The URI of the client registration endpoint. May
     *                    be {@code null} if the {@link #toHTTPRequest()}
     *                    method will not be used.
     * @param metadata    The client metadata. Must not be {@code null} and
     *                    must specify one or more redirection URIs.
     * @param accessToken An OAuth 2.0 Bearer access token for the request,
     *                    {@code null} if none.
     */
    public ClientRegistrationRequest(URI uri,
                                     ClientMetadata metadata,
                                     BearerAccessToken accessToken) {

        this(uri, metadata, null, accessToken);
    }


    /**
     * Creates a new client registration request with an optional software
     * statement.
     *
     * @param uri               The URI of the client registration
     *                          endpoint. May be {@code null} if the
     *                          {@link #toHTTPRequest()} method will not be
     *                          used.
     * @param metadata          The client metadata. Must not be
     *                          {@code null} and must specify one or more
     *                          redirection URIs.
     * @param softwareStatement Optional software statement, as a signed
     *                          JWT with an {@code iss} claim; {@code null}
     *                          if not specified.
     * @param accessToken       An OAuth 2.0 Bearer access token for the
     *                          request, {@code null} if none.
     */
    public ClientRegistrationRequest(URI uri,
                                     ClientMetadata metadata,
                                     SignedJWT softwareStatement,
                                     BearerAccessToken accessToken) {

        super(uri, accessToken);

        if (metadata == null) {
            throw new IllegalArgumentException("The client metadata must not be null");
        }

        this.metadata = metadata;


        if (softwareStatement != null) {

            if (softwareStatement.getState() == JWSObject.State.UNSIGNED) {
                throw new IllegalArgumentException("The software statement JWT must be signed");
            }

            JWTClaimsSet claimsSet;

            try {
                claimsSet = softwareStatement.getJWTClaimsSet();

            } catch (java.text.ParseException e) {

                throw new IllegalArgumentException("The software statement is not a valid signed JWT: " + e.getMessage());
            }

            if (claimsSet.getIssuer() == null) {

                // http://tools.ietf.org/html/rfc7591#section-2.3
                throw new IllegalArgumentException("The software statement JWT must contain an 'iss' claim");
            }

        }

        this.softwareStatement = softwareStatement;
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
     * Gets the software statement.
     *
     * @return The software statement, as a signed JWT with an {@code iss}
     * claim; {@code null} if not specified.
     */
    public SignedJWT getSoftwareStatement() {

        return softwareStatement;
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

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, endpointURL);

        if (getAccessToken() != null) {
            httpRequest.setAuthorization(getAccessToken().toAuthorizationHeader());
        }

        httpRequest.setContentType(CommonContentTypes.APPLICATION_JSON);

        JsonObjectBuilder content = metadata.toJSONObject();

        if (softwareStatement != null) {

            // Signed state check done in constructor
            content.add("software_statement", softwareStatement.serialize());
        }

        httpRequest.setQuery(content.build().toString());

        return httpRequest;
    }


    /**
     * Parses a client registration request from the specified HTTP POST
     * request.
     *
     * @param httpRequest The HTTP request. Must not be {@code null}.
     * @return The client registration request.
     * @throws OAuth2JSONParseException If the HTTP request couldn't be parsed to a
     *                                  client registration request.
     */
    public static ClientRegistrationRequest parse(HTTPRequest httpRequest)
            throws OAuth2JSONParseException {

        httpRequest.ensureMethod(HTTPRequest.Method.POST);

        // Get the JSON object content
        JsonObject jsonObject = httpRequest.getQueryAsJSONObject();

        // Extract the software statement if any
        SignedJWT stmt = null;

        if (jsonObject.containsKey("software_statement")) {

            try {
                stmt = SignedJWT.parse(jsonObject.getString("software_statement"));

            } catch (java.text.ParseException e) {

                throw new OAuth2JSONParseException("Invalid software statement JWT: " + e.getMessage());
            }

            // Prevent the JWT from appearing in the metadata

            jsonObject = JSONObjectUtils.remove(jsonObject, "software_statement");
        }

        // Parse the client metadata
        ClientMetadata metadata = ClientMetadata.parse(jsonObject);

        // Parse the optional bearer access token
        BearerAccessToken accessToken = null;

        String authzHeaderValue = httpRequest.getAuthorization();

        if (StringUtils.hasText(authzHeaderValue)) {
            accessToken = BearerAccessToken.parse(authzHeaderValue);
        }

        try {
            URI endpointURI = httpRequest.getURL().toURI();

            return new ClientRegistrationRequest(endpointURI, metadata, stmt, accessToken);

        } catch (URISyntaxException | IllegalArgumentException e) {

            throw new OAuth2JSONParseException(e.getMessage(), e);
        }
    }
}