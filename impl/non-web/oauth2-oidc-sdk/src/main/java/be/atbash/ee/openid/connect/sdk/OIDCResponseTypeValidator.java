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


import be.atbash.ee.oauth2.sdk.ResponseType;


/**
 * OpenID Connect response type validator.
 */
class OIDCResponseTypeValidator {


    /**
     * Checks if the specified response type is valid in OpenID Connect.
     *
     * @param rt The response type. Must not be {@code null}.
     * @throws IllegalArgumentException If the response type wasn't a valid
     *                                  OpenID Connect response type.
     */
    public static void validate(ResponseType rt) {

        if (rt.isEmpty()) {
            throw new IllegalArgumentException("The response type must contain at least one value");
        }

        if (rt.contains(ResponseType.Value.TOKEN) && rt.size() == 1) {
            throw new IllegalArgumentException("The OpenID Connect response type cannot have token as the only value");
        }

        for (ResponseType.Value rtValue : rt) {

            if (!rtValue.equals(ResponseType.Value.CODE) &&
                    !rtValue.equals(ResponseType.Value.TOKEN) &&
                    !rtValue.equals(OIDCResponseTypeValue.ID_TOKEN)) {
                throw new IllegalArgumentException("Unsupported OpenID Connect response type value: " + rtValue);
            }
        }
    }


    /**
     * Prevents public instantiation.
     */
    private OIDCResponseTypeValidator() {

    }
}
