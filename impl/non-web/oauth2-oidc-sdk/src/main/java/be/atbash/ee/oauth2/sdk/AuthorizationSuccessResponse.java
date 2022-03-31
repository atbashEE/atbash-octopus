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
package be.atbash.ee.oauth2.sdk;


import be.atbash.ee.oauth2.sdk.id.State;
import be.atbash.ee.oauth2.sdk.token.AccessToken;
import be.atbash.ee.oauth2.sdk.util.MultivaluedMapUtils;
import be.atbash.ee.security.octopus.nimbus.jwt.JWT;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTParser;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;

import jakarta.json.Json;
import jakarta.json.JsonObjectBuilder;
import jakarta.json.JsonValue;
import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * Authorisation success response. Used to return an authorisation code or
 * access token at the Authorisation endpoint.
 *
 * <p>Example HTTP response with code (code flow):
 *
 * <pre>
 * HTTP/1.1 302 Found
 * Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&amp;state=xyz
 * </pre>
 *
 * <p>Example HTTP response with access token (implicit flow):
 *
 * <pre>
 * HTTP/1.1 302 Found
 * Location: http://example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA
 *           &amp;state=xyz&amp;token_type=Bearer&amp;expires_in=3600
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 4.1.2 and 4.2.2.
 *     <li>OAuth 2.0 Multiple Response Type Encoding Practices 1.0.
 *     <li>OAuth 2.0 Form Post Response Mode 1.0.
 *     <li>Financial-grade API: JWT Secured Authorization Response Mode for
 *         OAuth 2.0 (JARM).
 * </ul>
 */
public class AuthorizationSuccessResponse
        extends AuthorizationResponse
        implements SuccessResponse {


    /**
     * The authorisation code, if requested.
     */
    private final AuthorizationCode code;


    /**
     * The access token, if requested.
     */
    private final AccessToken accessToken;


    /**
     * Creates a new authorisation success response.
     *
     * @param redirectURI The base redirection URI. Must not be
     *                    {@code null}.
     * @param code        The authorisation code, {@code null} if not
     *                    requested.
     * @param accessToken The access token, {@code null} if not requested.
     * @param state       The state, {@code null} if not specified.
     * @param rm          The response mode, {@code null} if not specified.
     */
    public AuthorizationSuccessResponse(URI redirectURI,
                                        AuthorizationCode code,
                                        AccessToken accessToken,
                                        State state,
                                        ResponseMode rm) {

        super(redirectURI, state, rm);
        this.code = code;
        this.accessToken = accessToken;
    }


    /**
     * Creates a new JSON Web Token (JWT) secured authorisation success
     * response.
     *
     * @param redirectURI The base redirection URI. Must not be
     *                    {@code null}.
     * @param jwtResponse The JWT-secured response. Must not be
     *                    {@code null}.
     * @param rm          The response mode, {@code null} if not specified.
     */
    public AuthorizationSuccessResponse(URI redirectURI,
                                        JWT jwtResponse,
                                        ResponseMode rm) {

        super(redirectURI, jwtResponse, rm);
        code = null;
        accessToken = null;
    }


    @Override
    public boolean indicatesSuccess() {

        return true;
    }


    @Override
    public ResponseMode impliedResponseMode() {
        // FIXME Unlikely it is used ion Octopus and needed there. Remove?
        if (getResponseMode() != null) {
            return getResponseMode();
        } else {
            if (getJWTResponse() != null) {
                // JARM
                return ResponseMode.JWT;
            } else if (accessToken != null) {
                return ResponseMode.FRAGMENT;
            } else {
                return ResponseMode.QUERY;
            }
        }
    }


    /**
     * Gets the authorisation code.
     *
     * @return The authorisation code, {@code null} if not requested.
     */
    public AuthorizationCode getAuthorizationCode() {

        return code;
    }


    /**
     * Gets the access token.
     *
     * @return The access token, {@code null} if not requested.
     */
    public AccessToken getAccessToken() {

        return accessToken;
    }


    @Override
    public Map<String, List<String>> toParameters() {

        Map<String, List<String>> params = new HashMap<>();

        if (getJWTResponse() != null) {
            // JARM, no other top-level parameters
            params.put("response", Collections.singletonList(getJWTResponse().serialize()));
            return params;
        }

        if (code != null) {
            params.put("code", Collections.singletonList(code.getValue()));
        }

        if (accessToken != null) {

            for (Map.Entry<String, JsonValue> entry : accessToken.toJSONObject().entrySet()) {

                params.put(entry.getKey(), Collections.singletonList(JSONObjectUtils.getJsonValueAsObject(entry.getValue()).toString()));
            }
        }

        if (getState() != null) {
            params.put("state", Collections.singletonList(getState().getValue()));
        }

        return params;
    }


    /**
     * Parses an authorisation success response.
     *
     * @param redirectURI The base redirection URI. Must not be
     *                    {@code null}.
     * @param params      The response parameters to parse. Must not be
     *                    {@code null}.
     * @return The authorisation success response.
     * @throws OAuth2JSONParseException If the parameters couldn't be parsed to an
     *                                  authorisation success response.
     */
    public static AuthorizationSuccessResponse parse(URI redirectURI,
                                                     Map<String, List<String>> params)
            throws OAuth2JSONParseException {

        // JARM, ignore other top level params
        if (params.get("response") != null) {
            JWT jwtResponse;
            try {
                jwtResponse = JWTParser.parse(MultivaluedMapUtils.getFirstValue(params, "response"));
            } catch (java.text.ParseException e) {
                throw new OAuth2JSONParseException("Invalid JWT response: " + e.getMessage(), e);
            }

            return new AuthorizationSuccessResponse(redirectURI, jwtResponse, ResponseMode.JWT);
        }

        // Parse code parameter
        AuthorizationCode code = null;

        if (params.get("code") != null) {
            code = new AuthorizationCode(MultivaluedMapUtils.getFirstValue(params, "code"));
        }

        // Parse access_token parameters
        AccessToken accessToken = null;

        if (params.get("access_token") != null) {

            JsonObjectBuilder jsonObject = Json.createObjectBuilder();

            for (Map.Entry<String, String> entry : MultivaluedMapUtils.toSingleValuedMap(params).entrySet()) {
                jsonObject.add(entry.getKey(), entry.getValue());
            }
            accessToken = AccessToken.parse(jsonObject.build());
        }

        // Parse optional state parameter
        State state = State.parse(MultivaluedMapUtils.getFirstValue(params, "state"));

        return new AuthorizationSuccessResponse(redirectURI, code, accessToken, state, null);
    }

}
