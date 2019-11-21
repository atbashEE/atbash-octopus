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
import be.atbash.ee.oauth2.sdk.id.Audience;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.security.octopus.nimbus.jwt.util.DateUtils;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;
import java.net.URI;
import java.text.ParseException;
import java.util.Date;


/**
 * Request object POST success response.
 *
 * <p>Example request object POST success response:
 *
 * <pre>
 * HTTP/1.1 201 Created
 * Date: Tue, 2 May 2017 15:22:31 GMT
 * Content-Type: application/json
 *
 * {
 *   "iss"         : "https://c2id.com",
 *   "aud"         : "s6bhdrkqt3",
 *   "request_uri" : "urn:requests:aashoo1Ooj6ahc5C",
 *   "exp"         : 1493738581
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Financial-grade API - Part 2: Read and Write API Security Profile,
 *         section 7.
 *     <li>The OAuth 2.0 Authorization Framework: JWT Secured Authorization
 *         Request (JAR) (draft-ietf-oauth-jwsreq-17).
 * </ul>
 */
@Deprecated
// FIXME Remove Deprecated stuff
public final class RequestObjectPOSTSuccessResponse extends RequestObjectPOSTResponse implements SuccessResponse {


    /**
     * The issuer.
     */
    private final Issuer iss;


    /**
     * The audience (client ID).
     */
    private final Audience aud;


    /**
     * The request URI.
     */
    private final URI requestURI;


    /**
     * The request URI expiration time.
     */
    private final Date exp;


    /**
     * Creates a new request object POST success response.
     *
     * @param iss        The issuer. Must not be {@code null}.
     * @param aud        The audience (the intended client IDMust not be
     *                   {@code null}.).
     * @param requestURI The request URI. Must not be {@code null}.
     * @param exp        The request URI expiration time. Must not be
     *                   {@code null}.
     */
    public RequestObjectPOSTSuccessResponse(final Issuer iss,
                                            final Audience aud,
                                            final URI requestURI,
                                            final Date exp) {
        if (iss == null) {
            throw new IllegalArgumentException("The issuer must not be null");
        }
        this.iss = iss;

        if (aud == null) {
            throw new IllegalArgumentException("The audience must not be null");
        }
        this.aud = aud;

        if (requestURI == null) {
            throw new IllegalArgumentException("The request URI must not be null");
        }
        this.requestURI = requestURI;

        if (exp == null) {
            throw new IllegalArgumentException("The request URI expiration time must not be null");
        }
        this.exp = exp;
    }


    /**
     * Returns the issuer.
     *
     * @return The issuer.
     */
    public Issuer getIssuer() {
        return iss;
    }


    /**
     * Returns the audience (the intended client ID).
     *
     * @return The audience.
     */
    public Audience getAudience() {
        return aud;
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
     * Returns the expiration time.
     *
     * @return The expiration time.
     */
    public Date getExpirationTime() {
        return exp;
    }


    @Override
    public boolean indicatesSuccess() {
        return true;
    }


    /**
     * Returns a JSON object representation of this request object POST
     * success response.
     *
     * @return The JSON object.
     */
    public JsonObject toJSONObject() {

        JsonObjectBuilder result = Json.createObjectBuilder();


        result.add("iss", iss.getValue());
        result.add("aud", aud.getValue());
        result.add("request_uri", requestURI.toString());
        result.add("exp", DateUtils.toSecondsSinceEpoch(exp));

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
     * Parses a request object POST success response from the specified
     * JSON object.
     *
     * @param jsonObject The JSON object to parse. Must not be {@code null}.
     * @return The request object POST success response.
     * @throws OAuth2JSONParseException If the JSON object couldn't be parsed to a
     *                                  request object POST success response.
     */
    public static RequestObjectPOSTSuccessResponse parse(final JsonObject jsonObject)
            throws OAuth2JSONParseException {

        if (!JSONObjectUtils.hasValue(jsonObject, "iss")) {
            throw new OAuth2JSONParseException("Missing JSON object member with key \"iss\"");
        }
        if (!JSONObjectUtils.hasValue(jsonObject, "aud")) {
            throw new OAuth2JSONParseException("Missing JSON object member with key \"aud\"");
        }
        if (!JSONObjectUtils.hasValue(jsonObject, "request_uri")) {
            throw new OAuth2JSONParseException("Missing JSON object member with key \"request_uri\"");
        }
        if (!JSONObjectUtils.hasValue(jsonObject, "exp")) {
            throw new OAuth2JSONParseException("Missing JSON object member with key \"exp\"");
        }
        try {
            return new RequestObjectPOSTSuccessResponse(
                    new Issuer(jsonObject.getString("iss")),
                    new Audience(jsonObject.getString("aud")),
                    JSONObjectUtils.getURI(jsonObject, "request_uri"),
                    DateUtils.fromSecondsSinceEpoch(jsonObject.getJsonNumber("exp").longValue()));
        } catch (ParseException e) {
            throw new OAuth2JSONParseException(e.getMessage(), e);
        }
    }


    /**
     * Parses a request object POST success response from the specified
     * HTTP response.
     *
     * @param httpResponse The HTTP response. Must not be {@code null}.
     * @return The request object POST success response.
     * @throws OAuth2JSONParseException If the HTTP response couldn't be parsed to a
     *                                  request object POST success response.
     */
    public static RequestObjectPOSTSuccessResponse parse(final HTTPResponse httpResponse)
            throws OAuth2JSONParseException {

        httpResponse.ensureStatusCode(HTTPResponse.SC_CREATED, HTTPResponse.SC_OK);
        return parse(httpResponse.getContentAsJSONObject());
    }
}
