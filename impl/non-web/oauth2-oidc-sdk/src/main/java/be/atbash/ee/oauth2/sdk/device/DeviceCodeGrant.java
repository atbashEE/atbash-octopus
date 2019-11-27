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


import be.atbash.ee.oauth2.sdk.AuthorizationGrant;
import be.atbash.ee.oauth2.sdk.GrantType;
import be.atbash.ee.oauth2.sdk.OAuth2Error;
import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.util.MultivaluedMapUtils;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;


/**
 * Device code grant for the OAuth 2.0 Device Authorization Grant.
 *
 * <p>
 * Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Device Authorization Grant (draft-ietf-oauth-device-flow-15)
 * </ul>
 */
public class DeviceCodeGrant extends AuthorizationGrant {


    /**
     * The grant type.
     */
    public static final GrantType GRANT_TYPE = GrantType.DEVICE_CODE;


    /**
     * The device code received from the authorisation server.
     */
    private final DeviceCode deviceCode;


    /**
     * Creates a new device code grant.
     *
     * @param deviceCode The device code. Must not be {@code null}.
     */
    public DeviceCodeGrant(DeviceCode deviceCode) {

        super(GRANT_TYPE);

        if (deviceCode == null) {
            throw new IllegalArgumentException("The device code must not be null");
        }

        this.deviceCode = deviceCode;
    }


    /**
     * Returns the device code received from the authorisation server.
     *
     * @return The device code received from the authorisation server.
     */
    public DeviceCode getDeviceCode() {

        return deviceCode;
    }


    @Override
    public Map<String, List<String>> toParameters() {

        Map<String, List<String>> params = new LinkedHashMap<>();
        params.put("grant_type", Collections.singletonList(GRANT_TYPE.getValue()));
        params.put("device_code", Collections.singletonList(deviceCode.getValue()));
        return params;
    }


    /**
     * Parses a device code grant from the specified request body
     * parameters.
     *
     * <p>Example:
     *
     * <pre>
     * grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code
     * &amp;device_code=GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS
     * </pre>
     *
     * @param params The parameters.
     * @return The device code grant.
     * @throws OAuth2JSONParseException If parsing failed.
     */
    public static DeviceCodeGrant parse(Map<String, List<String>> params) throws OAuth2JSONParseException {

        // Parse grant type
        String grantTypeString = MultivaluedMapUtils.getFirstValue(params, "grant_type");

        if (grantTypeString == null) {
            String msg = "Missing \"grant_type\" parameter";
            throw new OAuth2JSONParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
        }

        if (!GrantType.parse(grantTypeString).equals(GRANT_TYPE)) {
            String msg = "The \"grant_type\" must be " + GRANT_TYPE;
            throw new OAuth2JSONParseException(msg, OAuth2Error.UNSUPPORTED_GRANT_TYPE.appendDescription(": " + msg));
        }

        // Parse authorisation code
        String deviceCodeString = MultivaluedMapUtils.getFirstValue(params, "device_code");

        if (deviceCodeString == null || deviceCodeString.trim().isEmpty()) {
            String msg = "Missing or empty \"device_code\" parameter";
            throw new OAuth2JSONParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
        }

        DeviceCode deviceCode = new DeviceCode(deviceCodeString);

        return new DeviceCodeGrant(deviceCode);
    }


    @Override
    public boolean equals(Object o) {

        if (this == o) {
            return true;
        }
        if (!(o instanceof DeviceCodeGrant)) {
            return false;
        }

        DeviceCodeGrant deviceCodeGrant = (DeviceCodeGrant) o;
        return deviceCode.equals(deviceCodeGrant.deviceCode);
    }


    @Override
    public int hashCode() {

        return deviceCode.hashCode();
    }
}
