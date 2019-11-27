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
package be.atbash.ee.oauth2.sdk.client;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.ProtectedResourceRequest;
import be.atbash.ee.oauth2.sdk.SerializeException;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;


/**
 * Client read request.
 *
 * <p>Example HTTP request:
 *
 * <pre>
 * GET /register/s6BhdRkqt3 HTTP/1.1
 * Accept: application/json
 * Host: server.example.com
 * Authorization: Bearer reg-23410913-abewfq.123483
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Dynamic Client Registration Management Protocol (RFC
 *         7592), section 2.1.
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591), section
 *         2.
 * </ul>
 */
// FIXME Will we have dynamic client registration support in octopus?
public class ClientReadRequest extends ProtectedResourceRequest {


    /**
     * Creates a new client read request.
     *
     * @param uri         The URI of the client configuration endpoint. May
     *                    be {@code null} if the {@link #toHTTPRequest()}
     *                    method will not be used.
     * @param accessToken An OAuth 2.0 Bearer access token for the request.
     *                    Must not be {@code null}.
     */
    public ClientReadRequest(URI uri, BearerAccessToken accessToken) {

        super(uri, accessToken);

        if (accessToken == null) {
            throw new IllegalArgumentException("The access token must not be null");
        }
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

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, endpointURL);
        httpRequest.setAuthorization(getAccessToken().toAuthorizationHeader());
        return httpRequest;
    }


    /**
     * Parses a client read request from the specified HTTP GET request.
     *
     * @param httpRequest The HTTP request. Must not be {@code null}.
     * @return The client read request.
     * @throws OAuth2JSONParseException If the HTTP request couldn't be parsed to a
     *                                  client read request.
     */
    public static ClientReadRequest parse(HTTPRequest httpRequest)
            throws OAuth2JSONParseException {

        httpRequest.ensureMethod(HTTPRequest.Method.GET);

        BearerAccessToken accessToken = BearerAccessToken.parse(httpRequest.getAuthorization());

        URI endpointURI;

        try {
            endpointURI = httpRequest.getURL().toURI();

        } catch (URISyntaxException e) {

            throw new OAuth2JSONParseException(e.getMessage(), e);
        }

        return new ClientReadRequest(endpointURI, accessToken);
    }
}
