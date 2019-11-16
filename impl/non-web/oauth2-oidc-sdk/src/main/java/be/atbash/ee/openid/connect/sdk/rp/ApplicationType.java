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
package be.atbash.ee.openid.connect.sdk.rp;


/**
 * Enumeration of OpenID Connect client application types.
 */
public enum ApplicationType {


    /**
     * Native application.
     */
    NATIVE,


    /**
     * Web application.
     */
    WEB;


    /**
     * Gets the default application type.
     *
     * @return {@link #WEB}
     */
    public static ApplicationType getDefault() {

        return WEB;
    }


    /**
     * Returns the string identifier of this application type.
     *
     * @return The string identifier.
     */
    @Override
    public String toString() {

        return super.toString().toLowerCase();
    }
}