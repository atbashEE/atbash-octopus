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


import be.atbash.ee.oauth2.sdk.AbstractRequest;
import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.SerializeException;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.id.State;
import be.atbash.ee.oauth2.sdk.util.MultivaluedMapUtils;
import be.atbash.ee.oauth2.sdk.util.URIUtils;
import be.atbash.ee.oauth2.sdk.util.URLUtils;
import be.atbash.ee.security.octopus.nimbus.jwt.JWT;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTParser;
import be.atbash.util.StringUtils;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;


/**
 * Logout request initiated by an OpenID relying party (RP).
 *
 * <p>Example HTTP request:
 *
 * <pre>
 * https://server.example.com/op/logout?
 * id_token_hint=eyJhbGciOiJSUzI1NiJ9.eyJpc3Mi...
 * &amp;post_logout_redirect_uri=https%3A%2F%2Fclient.example.org%2Fpost-logout
 * &amp;state=af0ifjsldkj
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Session Management 1.0, section 5.
 * </ul>
 */
public class LogoutRequest extends AbstractRequest {


    /**
     * The ID token hint (recommended).
     */
    private final JWT idTokenHint;


    /**
     * The optional post-logout redirection URI.
     */
    private final URI postLogoutRedirectURI;


    /**
     * The optional state parameter.
     */
    private final State state;


    /**
     * Creates a new OpenID Connect logout request.
     *
     * @param uri                   The URI of the end-session endpoint.
     *                              May be {@code null} if the
     *                              {@link #toHTTPRequest} method will not
     *                              be used.
     * @param idTokenHint           The ID token hint (recommended),
     *                              {@code null} if not specified.
     * @param postLogoutRedirectURI The optional post-logout redirection
     *                              URI, {@code null} if not specified.
     * @param state                 The optional state parameter for the
     *                              post-logout redirection URI,
     *                              {@code null} if not specified.
     */
    public LogoutRequest(URI uri,
                         JWT idTokenHint,
                         URI postLogoutRedirectURI,
                         State state) {

        super(uri);

        this.idTokenHint = idTokenHint;

        this.postLogoutRedirectURI = postLogoutRedirectURI;

        if (postLogoutRedirectURI == null && state != null) {
            throw new IllegalArgumentException("The state parameter required a post-logout redirection URI");
        }

        this.state = state;
    }


    /**
     * Creates a new OpenID Connect logout request without a post-logout
     * redirection.
     *
     * @param uri         The URI of the end-session endpoint. May be
     *                    {@code null} if the {@link #toHTTPRequest} method
     *                    will not be used.
     * @param idTokenHint The ID token hint (recommended), {@code null} if
     *                    not specified.
     */
    public LogoutRequest(URI uri,
                         JWT idTokenHint) {

        this(uri, idTokenHint, null, null);
    }


    /**
     * Creates a new OpenID Connect logout request without a post-logout
     * redirection.
     *
     * @param uri The URI of the end-session endpoint. May be {@code null}
     *            if the {@link #toHTTPRequest} method will not be used.
     */
    public LogoutRequest(URI uri) {

        this(uri, null, null, null);
    }


    /**
     * Returns the ID token hint.
     *
     * @return The ID token hint, {@code null} if not specified.
     */
    public JWT getIDTokenHint() {

        return idTokenHint;
    }


    /**
     * Return the post-logout redirection URI.
     *
     * @return The post-logout redirection URI, {@code null} if not
     * specified.
     */
    public URI getPostLogoutRedirectionURI() {

        return postLogoutRedirectURI;
    }


    /**
     * Returns the state parameter for a post-logout redirection URI.
     *
     * @return The state parameter, {@code null} if not specified.
     */
    public State getState() {

        return state;
    }

    /**
     * Returns the URI query parameters for this logout request.
     *
     * <p>Example parameters:
     *
     * <pre>
     * id_token_hint = eyJhbGciOiJSUzI1NiJ9.eyJpc3Mi...
     * post_logout_redirect_uri = https://client.example.com/post-logout
     * state = af0ifjsldkj
     * </pre>
     *
     * @return The parameters.
     */
    public Map<String, List<String>> toParameters() {

        Map<String, List<String>> params = new LinkedHashMap<>();

        if (idTokenHint != null) {
            try {
                params.put("id_token_hint", Collections.singletonList(idTokenHint.serialize()));
            } catch (IllegalStateException e) {
                throw new SerializeException("Couldn't serialize ID token: " + e.getMessage(), e);
            }
        }

        if (postLogoutRedirectURI != null) {
            params.put("post_logout_redirect_uri", Collections.singletonList(postLogoutRedirectURI.toString()));
        }

        if (state != null) {
            params.put("state", Collections.singletonList(state.getValue()));
        }

        return params;
    }


    /**
     * Returns the URI query string for this logout request.
     *
     * <p>Note that the '?' character preceding the query string in an URI
     * is not included in the returned string.
     *
     * <p>Example URI query string:
     *
     * <pre>
     * id_token_hint = eyJhbGciOiJSUzI1NiJ9.eyJpc3Mi...
     * &amp;post_logout_redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fpost-logout
     * &amp;state=af0ifjsldkj
     * </pre>
     *
     * @return The URI query string.
     */
    public String toQueryString() {

        return URLUtils.serializeParameters(toParameters());
    }


    /**
     * Returns the complete URI representation for this logout request,
     * consisting of the {@link #getEndpointURI end-session endpoint URI}
     * with the {@link #toQueryString query string} appended.
     *
     * <p>Example URI:
     *
     * <pre>
     * https://server.example.com/logout?
     * id_token_hint = eyJhbGciOiJSUzI1NiJ9.eyJpc3Mi...
     * &amp;post_logout_redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fpost-logout
     * &amp;state=af0ifjsldkj
     * </pre>
     *
     * @return The URI representation.
     */
    public URI toURI() {

        if (getEndpointURI() == null) {
            throw new SerializeException("The end-session endpoint URI is not specified");
        }

        String query = toQueryString();

        if (StringUtils.hasText(query)) {
            query = '?' + query;
        }

        try {
            return new URI(getEndpointURI() + query);
        } catch (URISyntaxException e) {
            throw new SerializeException("Couldn't append query string: " + e.getMessage(), e);
        }
    }


    @Override
    public HTTPRequest toHTTPRequest() {

        if (getEndpointURI() == null) {
            throw new SerializeException("The endpoint URI is not specified");
        }

        HTTPRequest httpRequest;

        URL endpointURL;

        try {
            endpointURL = getEndpointURI().toURL();

        } catch (MalformedURLException e) {

            throw new SerializeException(e.getMessage(), e);
        }

        httpRequest = new HTTPRequest(HTTPRequest.Method.GET, endpointURL);

        httpRequest.setQuery(toQueryString());

        return httpRequest;
    }


    /**
     * Parses a logout request from the specified URI query parameters.
     *
     * <p>Example parameters:
     *
     * <pre>
     * id_token_hint = eyJhbGciOiJSUzI1NiJ9.eyJpc3Mi...
     * post_logout_redirect_uri = https://client.example.com/post-logout
     * state = af0ifjsldkj
     * </pre>
     *
     * @param params The parameters, empty map if none. Must not be
     *               {@code null}.
     * @return The logout request.
     * @throws OAuth2JSONParseException If the parameters couldn't be parsed to a
     *                                  logout request.
     */
    public static LogoutRequest parse(Map<String, List<String>> params)
            throws OAuth2JSONParseException {

        return parse(null, params);
    }


    /**
     * Parses a logout request from the specified URI and query parameters.
     *
     * <p>Example parameters:
     *
     * <pre>
     * id_token_hint = eyJhbGciOiJSUzI1NiJ9.eyJpc3Mi...
     * post_logout_redirect_uri = https://client.example.com/post-logout
     * state = af0ifjsldkj
     * </pre>
     *
     * @param uri    The URI of the end-session endpoint. May be
     *               {@code null} if the {@link #toHTTPRequest()} method
     *               will not be used.
     * @param params The parameters, empty map if none. Must not be
     *               {@code null}.
     * @return The logout request.
     * @throws OAuth2JSONParseException If the parameters couldn't be parsed to a
     *                                  logout request.
     */
    public static LogoutRequest parse(URI uri, Map<String, List<String>> params)
            throws OAuth2JSONParseException {

        String v = MultivaluedMapUtils.getFirstValue(params, "id_token_hint");

        JWT idTokenHint = null;

        if (StringUtils.hasText(v)) {

            try {
                idTokenHint = JWTParser.parse(v);
            } catch (java.text.ParseException e) {
                throw new OAuth2JSONParseException("Invalid ID token hint: " + e.getMessage(), e);
            }
        }

        v = MultivaluedMapUtils.getFirstValue(params, "post_logout_redirect_uri");

        URI postLogoutRedirectURI = null;

        if (StringUtils.hasText(v)) {

            try {
                postLogoutRedirectURI = new URI(v);
            } catch (URISyntaxException e) {
                throw new OAuth2JSONParseException("Invalid \"post_logout_redirect_uri\" parameter: " + e.getMessage(), e);
            }
        }

        State state = null;

        v = MultivaluedMapUtils.getFirstValue(params, "state");

        if (postLogoutRedirectURI != null && StringUtils.hasText(v)) {
            state = new State(v);
        }

        return new LogoutRequest(uri, idTokenHint, postLogoutRedirectURI, state);
    }


    /**
     * Parses a logout request from the specified URI query string.
     *
     * <p>Example URI query string:
     *
     * <pre>
     * id_token_hint = eyJhbGciOiJSUzI1NiJ9.eyJpc3Mi...
     * &amp;post_logout_redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fpost-logout
     * &amp;state=af0ifjsldkj
     * </pre>
     *
     * @param query The URI query string, {@code null} if none.
     * @return The logout request.
     * @throws OAuth2JSONParseException If the query string couldn't be parsed to a
     *                                  logout request.
     */
    public static LogoutRequest parse(String query)
            throws OAuth2JSONParseException {

        return parse(null, URLUtils.parseParameters(query));
    }


    /**
     * Parses a logout request from the specified URI query string.
     *
     * <p>Example URI query string:
     *
     * <pre>
     * id_token_hint = eyJhbGciOiJSUzI1NiJ9.eyJpc3Mi...
     * &amp;post_logout_redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fpost-logout
     * &amp;state=af0ifjsldkj
     * </pre>
     *
     * @param uri   The URI of the end-session endpoint. May be
     *              {@code null} if the {@link #toHTTPRequest()} method
     *              will not be used.
     * @param query The URI query string, {@code null} if none.
     * @return The logout request.
     * @throws OAuth2JSONParseException If the query string couldn't be parsed to a
     *                                  logout request.
     */
    public static LogoutRequest parse(URI uri, String query)
            throws OAuth2JSONParseException {

        return parse(uri, URLUtils.parseParameters(query));
    }


    /**
     * Parses a logout request from the specified URI.
     *
     * <p>Example URI:
     *
     * <pre>
     * https://server.example.com/logout?
     * id_token_hint = eyJhbGciOiJSUzI1NiJ9.eyJpc3Mi...
     * &amp;post_logout_redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fpost-logout
     * &amp;state=af0ifjsldkj
     * </pre>
     *
     * @param uri The URI. Must not be {@code null}.
     * @return The logout request.
     * @throws OAuth2JSONParseException If the URI couldn't be parsed to a logout
     *                                  request.
     */
    public static LogoutRequest parse(URI uri)
            throws OAuth2JSONParseException {

        return parse(URIUtils.getBaseURI(uri), URLUtils.parseParameters(uri.getRawQuery()));
    }


    /**
     * Parses a logout request from the specified HTTP request.
     *
     * <p>Example HTTP request (GET):
     *
     * <pre>
     * https://server.example.com/logout?
     * id_token_hint = eyJhbGciOiJSUzI1NiJ9.eyJpc3Mi...
     * &amp;post_logout_redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fpost-logout
     * &amp;state=af0ifjsldkj
     * </pre>
     *
     * @param httpRequest The HTTP request. Must not be {@code null}.
     * @return The logout request.
     * @throws OAuth2JSONParseException If the HTTP request couldn't be parsed to a
     *                                  logout request.
     */
    public static LogoutRequest parse(HTTPRequest httpRequest)
            throws OAuth2JSONParseException {

        String query = httpRequest.getQuery();

        if (query == null) {
            throw new OAuth2JSONParseException("Missing URI query string");
        }

        try {
            return parse(URIUtils.getBaseURI(httpRequest.getURL().toURI()), query);

        } catch (URISyntaxException e) {

            throw new OAuth2JSONParseException(e.getMessage(), e);
        }
    }
}
