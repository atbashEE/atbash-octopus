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


import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.oauth2.sdk.token.Tokens;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;

import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import java.util.*;


/**
 * Access token response from the Token endpoint.
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 200 OK
 * Content-Type: application/json;charset=UTF-8
 * Cache-Control: no-store
 * Pragma: no-cache
 *
 * {
 *   "access_token"      : "2YotnFZFEjr1zCsicMWpAA",
 *   "token_type"        : "example",
 *   "expires_in"        : 3600,
 *   "refresh_token"     : "tGzv3JOkF0XG5Qx2TlKWIA",
 *   "example_parameter" : "example_value"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 4.1.4, 4.3.3,  4.4.3 and 5.1.
 * </ul>
 */
public class AccessTokenResponse extends TokenResponse implements SuccessResponse {


    /**
     * The tokens.
     */
    private final Tokens tokens;


    /**
     * Optional custom parameters.
     */
    private final Map<String, Object> customParams;


    /**
     * Creates a new access token response.
     *
     * @param tokens The tokens. Must not be {@code null}.
     */
    public AccessTokenResponse(Tokens tokens) {

        this(tokens, null);
    }


    /**
     * Creates a new access token response.
     *
     * @param tokens       The tokens. Must not be {@code null}.
     * @param customParams Optional custom parameters, {@code null} if
     *                     none.
     */
    public AccessTokenResponse(Tokens tokens,
                               Map<String, Object> customParams) {

        if (tokens == null) {
            throw new IllegalArgumentException("The tokens must not be null");
        }

        this.tokens = tokens;

        this.customParams = customParams;
    }


    @Override
    public boolean indicatesSuccess() {

        return true;
    }


    /**
     * Returns the tokens.
     *
     * @return The tokens.
     */
    public Tokens getTokens() {

        return tokens;
    }


    /**
     * Returns the custom parameters.
     *
     * @return The custom parameters, as a unmodifiable map, empty map if
     * none.
     */
    public Map<String, Object> getCustomParameters() {

        if (customParams == null) {
            return Collections.emptyMap();
        }

        return Collections.unmodifiableMap(customParams);
    }


    @Deprecated
    public Map<String, Object> getCustomParams() {

        return getCustomParameters();
    }


    /**
     * Returns a JSON object representation of this access token response.
     *
     * <p>Example JSON object:
     *
     * <pre>
     * {
     *   "access_token"  : "SlAV32hkKG",
     *   "token_type"    : "Bearer",
     *   "refresh_token" : "8xLOxBtZp8",
     *   "expires_in"    : 3600
     * }
     * </pre>
     *
     * @return The JSON object.
     */
    public JsonObjectBuilder toJSONObject() {

        JsonObjectBuilder result = tokens.toJSONObject();

        if (customParams != null) {
            for (Map.Entry<String, Object> entry : customParams.entrySet()) {
                JSONObjectUtils.addValue(result, entry.getKey(), entry.getValue());
            }

        }

        return result;
    }


    @Override
    public HTTPResponse toHTTPResponse() {

        HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);

        httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
        httpResponse.setCacheControl("no-store");
        httpResponse.setPragma("no-cache");

        httpResponse.setContent(toJSONObject().build().toString());

        return httpResponse;
    }


    /**
     * Parses an access token response from the specified JSON object.
     *
     * @param jsonObject The JSON object to parse. Must not be {@code null}.
     * @return The access token response.
     * @throws OAuth2JSONParseException If the JSON object couldn't be parsed to an
     *                                  access token response.
     */
    public static AccessTokenResponse parse(JsonObject jsonObject)
            throws OAuth2JSONParseException {

        Tokens tokens = Tokens.parse(jsonObject);

        // Determine the custom param names
        Set<String> customParamNames = new HashSet<>(jsonObject.keySet());
        customParamNames.removeAll(tokens.getParameterNames());

        Map<String, Object> customParams = null;

        if (!customParamNames.isEmpty()) {

            customParams = new HashMap<>();

            for (String name : customParamNames) {
                customParams.put(name, JSONObjectUtils.getJsonValueAsObject(jsonObject.get(name)));
            }
        }

        return new AccessTokenResponse(tokens, customParams);
    }


    /**
     * Parses an access token response from the specified HTTP response.
     *
     * @param httpResponse The HTTP response. Must not be {@code null}.
     * @return The access token response.
     * @throws OAuth2JSONParseException If the HTTP response couldn't be parsed to an
     *                                  access token response.
     */
    public static AccessTokenResponse parse(HTTPResponse httpResponse)
            throws OAuth2JSONParseException {

        httpResponse.ensureStatusCode(HTTPResponse.SC_OK);
        JsonObject jsonObject = httpResponse.getContentAsJSONObject();
        return parse(jsonObject);
    }
}
