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
package be.atbash.ee.oauth2.sdk.id;


/**
 * Version identifier for an OAuth 2.0 client software.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591), section
 *         2.
 * </ul>
 */
public final class SoftwareVersion extends Identifier {


    /**
     * Creates a new OAuth 2.0 client software version identifier with the
     * specified value.
     *
     * @param value The software version identifier value. Must not be
     *              {@code null} or empty string.
     */
    public SoftwareVersion(final String value) {

        super(value);
    }


    @Override
    public boolean equals(final Object object) {

        return object instanceof SoftwareVersion &&
                this.toString().equals(object.toString());
    }
}
