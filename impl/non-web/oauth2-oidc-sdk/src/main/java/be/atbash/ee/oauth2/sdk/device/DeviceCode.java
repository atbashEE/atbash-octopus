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


import be.atbash.ee.oauth2.sdk.id.Identifier;

/**
 * Device code.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Device Authorization Grant (draft-ietf-oauth-device-flow-15)
 * </ul>
 */
public final class DeviceCode extends Identifier {


    /**
     * Creates a new device code with the specified value.
     *
     * @param value The code value. Must not be {@code null} or empty
     *              string.
     */
    public DeviceCode(String value) {

        super(value);
    }


    /**
     * Creates a new device code with a randomly generated value of the
     * specified byte length, Base64URL-encoded.
     *
     * @param byteLength The byte length of the value to generate. Must be
     *                   greater than one.
     */
    public DeviceCode(int byteLength) {

        super(byteLength);
    }


    /**
     * Creates a new device code with a randomly generated 256-bit (32-byte)
     * value, Base64URL-encoded.
     */
    public DeviceCode() {

        super();
    }


    @Override
    public boolean equals(Object object) {

        return object instanceof DeviceCode && this.toString().equals(object.toString());
    }
}
