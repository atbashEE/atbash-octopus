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
package be.atbash.ee.oauth2.sdk.device;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.Response;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;

import jakarta.json.JsonObject;


/**
 * Token endpoint response. This is the base abstract class for device
 * authorization success and error responses.
 *
 * <p>
 * Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Device Authorization Grant (draft-ietf-oauth-device-flow-15)
 * </ul>
 */
public abstract class DeviceAuthorizationResponse implements Response {


    /**
     * Casts this response to an authorization success response.
     *
     * @return The authorization success response.
     */
    public DeviceAuthorizationSuccessResponse toSuccessResponse() {

        return (DeviceAuthorizationSuccessResponse) this;
    }


    /**
     * Casts this response to a device authorization error response.
     *
     * @return The device authorization error response.
     */
    public DeviceAuthorizationErrorResponse toErrorResponse() {

        return (DeviceAuthorizationErrorResponse) this;
    }


    /**
     * Parses a device authorization response from the specified JSON
     * object.
     *
     * @param jsonObject The JSON object to parse. Must not be
     *                   {@code null}.
     * @return The device authorization success or error response.
     * @throws OAuth2JSONParseException If the JSON object couldn't be parsed to a
     *                                  device authorization response.
     */
    public static DeviceAuthorizationResponse parse(JsonObject jsonObject) throws OAuth2JSONParseException {

        if (jsonObject.containsKey("device_code")) {
            return DeviceAuthorizationSuccessResponse.parse(jsonObject);
        } else {
            return DeviceAuthorizationErrorResponse.parse(jsonObject);
        }
    }


    /**
     * Parses a device authorization response from the specified HTTP
     * response.
     *
     * @param httpResponse The HTTP response. Must not be {@code null}.
     * @return The device authorization sucess or error response.
     * @throws OAuth2JSONParseException If the HTTP response couldn't be parsed to a
     *                                  device authorization response.
     */
    public static DeviceAuthorizationResponse parse(HTTPResponse httpResponse) throws OAuth2JSONParseException {

        if (httpResponse.getStatusCode() == HTTPResponse.SC_OK) {
            return DeviceAuthorizationSuccessResponse.parse(httpResponse);
        } else {
            return DeviceAuthorizationErrorResponse.parse(httpResponse);
        }
    }
}