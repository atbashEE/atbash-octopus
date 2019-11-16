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


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.ProtectedResourceRequest;
import be.atbash.ee.oauth2.sdk.SerializeException;
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;


/**
 * UserInfo request. Used to retrieve the consented claims about the end-user.
 *
 * <p>Example HTTP GET request:
 *
 * <pre>
 * GET /userinfo HTTP/1.1
 * Host: server.example.com
 * Authorization: Bearer SlAV32hkKG
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 5.3.1.
 *     <li>OAuth 2.0 Bearer Token Usage (RFC6750), section 2.
 * </ul>
 */
public class UserInfoRequest extends ProtectedResourceRequest {


    /**
     * The HTTP method.
     */
    private final HTTPRequest.Method httpMethod;


    /**
     * Creates a new UserInfo HTTP GET request.
     *
     * @param uri         The URI of the UserInfo endpoint. May be
     *                    {@code null} if the {@link #toHTTPRequest} method
     *                    will not be used.
     * @param accessToken An OAuth 2.0 Bearer access token for the request.
     *                    Must not be {@code null}.
     */
    public UserInfoRequest(final URI uri, final BearerAccessToken accessToken) {

        this(uri, HTTPRequest.Method.GET, accessToken);
    }


    /**
     * Creates a new UserInfo request.
     *
     * @param uri         The URI of the UserInfo endpoint. May be
     *                    {@code null} if the {@link #toHTTPRequest} method
     *                    will not be used.
     * @param httpMethod  The HTTP method. Must be HTTP GET or POST and not
     *                    {@code null}.
     * @param accessToken An OAuth 2.0 Bearer access token for the request.
     *                    Must not be {@code null}.
     */
    public UserInfoRequest(final URI uri, final HTTPRequest.Method httpMethod, final BearerAccessToken accessToken) {

        super(uri, accessToken);

        if (httpMethod == null) {
            throw new IllegalArgumentException("The HTTP method must not be null");
        }

        this.httpMethod = httpMethod;


        if (accessToken == null) {
            throw new IllegalArgumentException("The access token must not be null");
        }
    }


    /**
     * Gets the HTTP method for this UserInfo request.
     *
     * @return The HTTP method.
     */
    public HTTPRequest.Method getMethod() {

        return httpMethod;
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

        HTTPRequest httpRequest = new HTTPRequest(httpMethod, endpointURL);

        switch (httpMethod) {

            case GET:
                httpRequest.setAuthorization(getAccessToken().toAuthorizationHeader());
                break;

            case POST:
                httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
                httpRequest.setQuery("access_token=" + getAccessToken().getValue());
                break;

            default:
                throw new SerializeException("Unexpected HTTP method: " + httpMethod);
        }

        return httpRequest;
    }


    /**
     * Parses the specified HTTP request for a UserInfo request.
     *
     * @param httpRequest The HTTP request. Must not be {@code null}.
     * @return The UserInfo request.
     * @throws OAuth2JSONParseException If the HTTP request couldn't be parsed to a
     *                                  UserInfo request.
     */
    public static UserInfoRequest parse(final HTTPRequest httpRequest)
            throws OAuth2JSONParseException {

        HTTPRequest.Method httpMethod = httpRequest.getMethod();

        BearerAccessToken accessToken = BearerAccessToken.parse(httpRequest);

        URI endpointURI;

        try {

            endpointURI = httpRequest.getURL().toURI();

        } catch (URISyntaxException e) {

            throw new OAuth2JSONParseException(e.getMessage(), e);
        }

        return new UserInfoRequest(endpointURI, httpMethod, accessToken);
    }
}
