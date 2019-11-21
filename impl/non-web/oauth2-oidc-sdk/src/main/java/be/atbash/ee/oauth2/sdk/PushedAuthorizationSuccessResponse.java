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
package be.atbash.ee.oauth2.sdk;


import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.net.URI;
import java.text.ParseException;


/**
 * Pushed authorisation success response.
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 201 Created
 * Date: Tue, 2 May 2017 15:22:31 GMT
 * Content-Type: application/json
 *
 * {
 *   "request_uri" : "urn:example:bwc4JK-ESC0w8acc191e-Y1LTC2",
 *   "expires_in"  : 3600
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Pushed Authorization Requests
 *         (draft-lodderstedt-oauth-par-01)
 * </ul>
 */
public class PushedAuthorizationSuccessResponse extends PushedAuthorizationResponse {


    /**
     * The request URI.
     */
    private final URI requestURI;


    /**
     * Lifetime, in seconds.
     */
    private final long lifetime;


    /**
     * Creates a new pushed authorisation success response.
     *
     * @param requestURI The request URI. Must not be {@code null}.
     * @param lifetime   The request lifetime, in seconds. Must be a
     *                   positive integer.
     */
    public PushedAuthorizationSuccessResponse(final URI requestURI, final long lifetime) {
        if (requestURI == null) {
            throw new IllegalArgumentException("The request URI must not be null");
        }
        this.requestURI = requestURI;
        if (lifetime <= 0) {
            throw new IllegalArgumentException("The request lifetime must be a positive integer");
        }
        this.lifetime = lifetime;
    }


    /**
     * Returns the request URI.
     *
     * @return The request URI.
     */
    public URI getRequestURI() {
        return requestURI;
    }


    /**
     * Returns the request lifetime.
     *
     * @return The request lifetime, in seconds.
     */
    public long getLifetime() {
        return lifetime;
    }


    @Override
    public boolean indicatesSuccess() {
        return true;
    }


    /**
     * Returns a JSON object representation of this pushed authorisation
     * success response.
     *
     * <p>Example JSON object:
     *
     * <pre>
     * {
     *   "request_uri": "urn:example:bwc4JK-ESC0w8acc191e-Y1LTC2",
     *   "expires_in": 3600
     * }
     * </pre>
     *
     * @return The JSON object.
     */
    public JsonObject toJSONObject() {

        JsonObjectBuilder result = Json.createObjectBuilder();
        result.add("request_uri", getRequestURI().toString());
        result.add("expires_in", getLifetime());
        return result.build();
    }


    @Override
    public HTTPResponse toHTTPResponse() {

        HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_CREATED);
        httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
        httpResponse.setContent(toJSONObject().toString());
        return httpResponse;
    }


    /**
     * Parses pushed authorisation success response from the specified JSON
     * object.
     *
     * @param jsonObject The JSON object to parse. Must not be
     *                   {@code null}.
     * @return The pushed authorisation success response.
     * @throws OAuth2JSONParseException If the JSON object couldn't be parsed to a
     *                                  pushed authorisation success response.
     */
    public static PushedAuthorizationSuccessResponse parse(final JsonObject jsonObject)
            throws OAuth2JSONParseException {

        URI requestURI = null;
        if (!JSONObjectUtils.hasValue(jsonObject,"request_uri")) {
            throw new OAuth2JSONParseException("Missing JSON object member with key \"request_uri\"");
        }
        try {
            requestURI = JSONObjectUtils.getURI(jsonObject, "request_uri");
        } catch (ParseException e) {
            throw new OAuth2JSONParseException(e.getMessage(), e);
        }
        if (!JSONObjectUtils.hasValue(jsonObject,"expires_in")) {
            throw new OAuth2JSONParseException("Missing JSON object member with key \"expires_in\"");
        }
        long lifetime = jsonObject.getJsonNumber("expires_in").longValue();
        return new PushedAuthorizationSuccessResponse(requestURI, lifetime);
    }


    /**
     * Parses a pushed authorisation success response from the specified
     * HTTP response.
     *
     * @param httpResponse The HTTP response. Must not be {@code null}.
     * @return The pushed authorisation success response.
     * @throws OAuth2JSONParseException If the HTTP response couldn't be parsed to a
     *                                  pushed authorisation success response.
     */
    public static PushedAuthorizationSuccessResponse parse(final HTTPResponse httpResponse)
            throws OAuth2JSONParseException {

        httpResponse.ensureStatusCode(HTTPResponse.SC_CREATED, HTTPResponse.SC_OK);
        JsonObject jsonObject = httpResponse.getContentAsJSONObject();
        return parse(jsonObject);
    }
}
