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
package be.atbash.ee.oauth2.sdk.auth.verifier;


import be.atbash.ee.oauth2.sdk.ErrorObject;
import be.atbash.ee.oauth2.sdk.GeneralException;
import be.atbash.ee.oauth2.sdk.OAuth2Error;

/**
 * Invalid client exception. Selected static instances are provided to speed up
 * exception processing.
 */
public class InvalidClientException extends GeneralException {


    /**
     * Bad {@code client_id}.
     */
    public static final InvalidClientException BAD_ID = new InvalidClientException("Bad client ID");


    /**
     * The client is not registered for the requested authentication
     * method.
     */
    public static final InvalidClientException NOT_REGISTERED_FOR_AUTH_METHOD = new InvalidClientException("The client is not registered for the requested authentication method");


    /**
     * The client has no registered {@code client_secret}.
     */
    public static final InvalidClientException NO_REGISTERED_SECRET = new InvalidClientException("The client has no registered secret");


    /**
     * The client has no registered JWK set.
     */
    public static final InvalidClientException NO_REGISTERED_JWK_SET = new InvalidClientException("The client has no registered JWK set");


    /**
     * Expired {@code client_secret}.
     */
    public static final InvalidClientException EXPIRED_SECRET = new InvalidClientException("Expired client secret");


    /**
     * Bad {@code client_secret}.
     */
    public static final InvalidClientException BAD_SECRET = new InvalidClientException("Bad client secret");


    /**
     * Bad JWT HMAC.
     */
    public static final InvalidClientException BAD_JWT_HMAC = new InvalidClientException("Bad JWT HMAC");


    /**
     * No matching public JWKs for JWT signature verification found.
     */
    public static final InvalidClientException NO_MATCHING_JWK = new InvalidClientException("No matching JWKs found");


    /**
     * Bad JWT signature.
     */
    public static final InvalidClientException BAD_JWT_SIGNATURE = new InvalidClientException("Bad JWT signature");


    /**
     * Bad self-signed client X.509 certificate.
     */
    public static final InvalidClientException BAD_SELF_SIGNED_CLIENT_CERTIFICATE = new InvalidClientException("Couldn't validate client X.509 certificate signature: No matching registered client JWK found");


    /**
     * Creates a new invalid client exception.
     *
     * @param message The message. Will not be appended to the OAuth 2.0
     *                error description to be prevent exposing details
     *                about why authentication didn't succeed to the
     *                client.
     */
    public InvalidClientException(String message) {
        super(message);
    }


    /**
     * Returns an OAuth 2.0 error object representation.
     *
     * @return {@link OAuth2Error#INVALID_CLIENT}.
     */
    @Override
    public ErrorObject getErrorObject() {
        return OAuth2Error.INVALID_CLIENT;
    }
}
