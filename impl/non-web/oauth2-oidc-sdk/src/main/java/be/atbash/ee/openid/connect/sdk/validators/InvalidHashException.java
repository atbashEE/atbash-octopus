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
package be.atbash.ee.openid.connect.sdk.validators;


/**
 * Invalid access token / code hash exception.
 */
public class InvalidHashException extends Exception {


    /**
     * Access token hash mismatch exception.
     */
    public static final InvalidHashException INVALID_ACCESS_T0KEN_HASH_EXCEPTION
            = new InvalidHashException("Access token hash (at_hash) mismatch");


    /**
     * Authorisation code hash mismatch exception.
     */
    public static final InvalidHashException INVALID_CODE_HASH_EXCEPTION
            = new InvalidHashException("Authorization code hash (c_hash) mismatch");


    /**
     * State hash mismatch exception.
     */
    public static final InvalidHashException INVALID_STATE_HASH_EXCEPTION
            = new InvalidHashException("State hash (s_hash) mismatch");


    /**
     * Creates a new invalid hash exception.
     *
     * @param message The exception message.
     */
    private InvalidHashException(String message) {
        super(message);
    }
}
