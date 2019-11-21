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
package be.atbash.ee.oauth2.sdk.device;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.SuccessResponse;
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;
import java.net.URI;
import java.text.ParseException;
import java.util.*;


/**
 * A device authorization response from the device authorization endpoint.
 *
 * <p>
 * Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 200 OK
 * Content-Type: application/json;charset=UTF-8
 * Cache-Control: no-store
 * Pragma: no-cache
 *
 * {
 *   "device_code"               : "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
 *   "user_code"                 : "WDJB-MJHT",
 *   "verification_uri"          : "https://example.com/device",
 *   "verification_uri_complete" : "https://example.com/device?user_code=WDJB-MJHT",
 *   "expires_in"                : 1800,
 *   "interval"                  : 5
 * }
 * </pre>
 *
 * <p>
 * Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Device Authorization Grant (draft-ietf-oauth-device-flow-15)
 *         section 3.2.
 * </ul>
 */
public class DeviceAuthorizationSuccessResponse extends DeviceAuthorizationResponse implements SuccessResponse {


    /**
     * The registered parameter names.
     */
    private static final Set<String> REGISTERED_PARAMETER_NAMES;

    static {
        Set<String> p = new HashSet<>();

        p.add("device_code");
        p.add("user_code");
        p.add("verification_uri");
        p.add("verification_uri_complete");
        p.add("expires_in");
        p.add("interval");

        REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
    }


    /**
     * The device verification code.
     */
    private final DeviceCode deviceCode;


    /**
     * The end-user verification code.
     */
    private final UserCode userCode;


    /**
     * The end-user verification URI on the authorization server. The URI
     * should be and easy to remember as end-users will be asked to
     * manually type it into their user-agent.
     */
    private final URI verificationURI;


    /**
     * Optional. A verification URI that includes the "user_code" (or other
     * information with the same function as the "user_code"), designed for
     * non-textual transmission.
     */
    private final URI verificationURIComplete;


    /**
     * The lifetime in seconds of the "device_code" and "user_code".
     */
    private final long lifetime;


    /**
     * Optional. The minimum amount of time in seconds that the client
     * SHOULD wait between polling requests to the token endpoint. If no
     * value is provided, clients MUST use 5 as the default.
     */
    private final long interval;


    /**
     * Optional custom parameters.
     */
    private final Map<String, Object> customParams;


    /**
     * Creates a new device authorization success response.
     *
     * @param deviceCode      The device verification code. Must not be
     *                        {@code null}.
     * @param userCode        The user verification code. Must not be
     *                        {@code null}.
     * @param verificationURI The end-user verification URI on the
     *                        authorization server. Must not be
     *                        {@code null}.
     * @param lifetime        The lifetime in seconds of the "device_code"
     *                        and "user_code".
     */
    public DeviceAuthorizationSuccessResponse(final DeviceCode deviceCode,
                                              final UserCode userCode,
                                              final URI verificationURI,
                                              final long lifetime) {

        this(deviceCode, userCode, verificationURI, null, lifetime, 5, null);
    }


    /**
     * Creates a new device authorization success response.
     *
     * @param deviceCode              The device verification code. Must
     *                                not be {@code null}.
     * @param userCode                The user verification code. Must not
     *                                be {@code null}.
     * @param verificationURI         The end-user verification URI on the
     *                                authorization server. Must not be
     *                                {@code null}.
     * @param verificationURIComplete The end-user verification URI on the
     *                                authorization server that includes
     *                                the user_code. Can be {@code null}.
     * @param lifetime                The lifetime in seconds of the
     *                                "device_code" and "user_code". Must
     *                                be greater than {@code 0}.
     * @param interval                The minimum amount of time in seconds
     *                                that the client SHOULD wait between
     *                                polling requests to the token
     *                                endpoint.
     * @param customParams            Optional custom parameters,
     *                                {@code null} if none.
     */
    public DeviceAuthorizationSuccessResponse(final DeviceCode deviceCode,
                                              final UserCode userCode,
                                              final URI verificationURI,
                                              final URI verificationURIComplete,
                                              final long lifetime,
                                              final long interval,
                                              final Map<String, Object> customParams) {

        if (deviceCode == null) {
            throw new IllegalArgumentException("The device_code must not be null");
        }

        this.deviceCode = deviceCode;

        if (userCode == null) {
            throw new IllegalArgumentException("The user_code must not be null");
        }

        this.userCode = userCode;

        if (verificationURI == null) {
            throw new IllegalArgumentException("The verification_uri must not be null");
        }

        this.verificationURI = verificationURI;

        this.verificationURIComplete = verificationURIComplete;

        if (lifetime <= 0) {
            throw new IllegalArgumentException("The lifetime must be greater than 0");
        }

        this.lifetime = lifetime;
        this.interval = interval;
        this.customParams = customParams;
    }


    /**
     * Returns the registered (standard) OAuth 2.0 device authorization
     * response parameter names.
     *
     * @return The registered OAuth 2.0 device authorization response
     * parameter names, as a unmodifiable set.
     */
    public static Set<String> getRegisteredParameterNames() {

        return REGISTERED_PARAMETER_NAMES;
    }


    @Override
    public boolean indicatesSuccess() {

        return true;
    }


    /**
     * Returns the device verification code.
     *
     * @return The device verification code.
     */
    public DeviceCode getDeviceCode() {

        return deviceCode;
    }


    /**
     * Returns the end-user verification code.
     *
     * @return The end-user verification code.
     */
    public UserCode getUserCode() {

        return userCode;
    }


    /**
     * Returns the end-user verification URI on the authorization server.
     *
     * @return The end-user verification URI on the authorization server.
     */
    public URI getVerificationURI() {

        return verificationURI;
    }


    /**
     * @see #getVerificationURI()
     */
    @Deprecated
    public URI getVerificationUri() {

        return getVerificationURI();
    }


    /**
     * Returns the end-user verification URI that includes the user_code.
     *
     * @return The end-user verification URI that includes the user_code,
     * or {@code null} if not specified.
     */
    public URI getVerificationURIComplete() {

        return verificationURIComplete;
    }


    /**
     * @see #getVerificationURIComplete()
     */
    @Deprecated
    public URI getVerificationUriComplete() {

        return getVerificationURIComplete();
    }


    /**
     * Returns the lifetime in seconds of the "device_code" and "user_code".
     *
     * @return The lifetime in seconds of the "device_code" and "user_code".
     */
    public long getLifetime() {

        return lifetime;
    }


    /**
     * Returns the minimum amount of time in seconds that the client SHOULD
     * wait between polling requests to the token endpoint.
     *
     * @return The minimum amount of time in seconds that the client SHOULD
     * wait between polling requests to the token endpoint.
     */
    public long getInterval() {

        return interval;
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


    /**
     * Returns a JSON object representation of this device authorization
     * response.
     *
     * <p>
     * Example JSON object:
     *
     * <pre>
     * {
     *   "device_code"               : "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
     *   "user_code"                 : "WDJB-MJHT",
     *   "verification_uri"          : "https://example.com/device",
     *   "verification_uri_complete" : "https://example.com/device?user_code=WDJB-MJHT",
     *   "expires_in"                : 1800,
     *   "interval"                  : 5
     * }
     * </pre>
     *
     * @return The JSON object.
     */
    public JsonObject toJSONObject() {

        JsonObjectBuilder result = Json.createObjectBuilder();
        result.add("device_code", getDeviceCode().toString());
        result.add("user_code", getUserCode().toString());
        result.add("verification_uri", getVerificationURI().toString());

        if (getVerificationURIComplete() != null) {
            result.add("verification_uri_complete", getVerificationURIComplete().toString());
        }

        result.add("expires_in", getLifetime());

        if (getInterval() > 0) {
            result.add("interval", getInterval());
        }

        if (customParams != null) {
            for (Map.Entry<String, Object> entry : customParams.entrySet()) {
                JSONObjectUtils.addValue(result, entry.getKey(), entry.getValue());
            }

        }

        return result.build();
    }


    @Override
    public HTTPResponse toHTTPResponse() {

        HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);

        httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
        httpResponse.setCacheControl("no-store");
        httpResponse.setPragma("no-cache");

        httpResponse.setContent(toJSONObject().toString());

        return httpResponse;
    }


    /**
     * Parses an device authorization response from the specified JSON
     * object.
     *
     * @param jsonObject The JSON object to parse. Must not be {@code null}.
     * @return The device authorization response.
     * @throws OAuth2JSONParseException If the JSON object couldn't be parsed to a
     *                                  device authorization response.
     */
    public static DeviceAuthorizationSuccessResponse parse(final JsonObject jsonObject) throws OAuth2JSONParseException {

        if (!JSONObjectUtils.hasValue(jsonObject, "device_code")) {
            throw new OAuth2JSONParseException("Missing JSON object member with key \"device_code\"");
        }
        DeviceCode deviceCode = new DeviceCode(jsonObject.getString("device_code"));
        if (!JSONObjectUtils.hasValue(jsonObject, "user_code")) {
            throw new OAuth2JSONParseException("Missing JSON object member with key \"user_code\"");
        }
        UserCode userCode = new UserCode(jsonObject.getString("user_code", null));
        URI verificationURI;
        URI verificationURIComplete;
        try {
            verificationURI = JSONObjectUtils.getURI(jsonObject, "verification_uri");
            verificationURIComplete = JSONObjectUtils.getURI(jsonObject, "verification_uri_complete");
        } catch (ParseException e) {
            throw new OAuth2JSONParseException(e.getMessage(), e);
        }

        // Parse lifetime
        long lifetime;
        if (jsonObject.get("expires_in").getValueType() == JsonValue.ValueType.NUMBER) {

            lifetime = jsonObject.getJsonNumber("expires_in").longValue();
        } else {
            String lifetimeStr = jsonObject.getString("expires_in");

            try {
                lifetime = Long.parseLong(lifetimeStr);

            } catch (NumberFormatException e) {

                throw new OAuth2JSONParseException("Invalid expires_in parameter, must be integer");
            }
        }

        // Parse lifetime
        long interval = 5;
        if (jsonObject.containsKey("interval")) {
            if (jsonObject.get("interval").getValueType() == JsonValue.ValueType.NUMBER) {

                interval = jsonObject.getJsonNumber("interval").longValue();
            } else {
                String intervalStr = jsonObject.getString("interval");

                try {
                    interval = Long.parseLong(intervalStr);

                } catch (NumberFormatException e) {

                    throw new OAuth2JSONParseException("Invalid \"interval\" parameter, must be integer");
                }
            }
        }

        // Determine the custom param names
        Set<String> customParamNames = new HashSet<>();
        customParamNames.addAll(jsonObject.keySet());
        customParamNames.removeAll(getRegisteredParameterNames());

        Map<String, Object> customParams = null;

        if (!customParamNames.isEmpty()) {

            customParams = new LinkedHashMap<>();

            for (String name : customParamNames) {
                customParams.put(name, JSONObjectUtils.getJsonValueAsObject(jsonObject.get(name)));
            }
        }

        return new DeviceAuthorizationSuccessResponse(deviceCode, userCode, verificationURI,
                verificationURIComplete, lifetime, interval, customParams);
    }


    /**
     * Parses an device authorization response from the specified HTTP
     * response.
     *
     * @param httpResponse The HTTP response. Must not be {@code null}.
     * @return The device authorization response.
     * @throws OAuth2JSONParseException If the HTTP response couldn't be parsed to a
     *                                  device authorization response.
     */
    public static DeviceAuthorizationSuccessResponse parse(final HTTPResponse httpResponse) throws OAuth2JSONParseException {

        httpResponse.ensureStatusCode(HTTPResponse.SC_OK);
        JsonObject jsonObject = httpResponse.getContentAsJSONObject();
        return parse(jsonObject);
    }
}
