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
package be.atbash.ee.oauth2.sdk.client;


import be.atbash.ee.oauth2.sdk.ErrorObject;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;

/**
 * OAuth 2.0 client registration errors.
 */
public final class RegistrationError {


    /**
     * Client registration: The value of one or more {@code redirect_uris}
     * is invalid.
     */
    public static final ErrorObject INVALID_REDIRECT_URI =
            new ErrorObject("invalid_redirect_uri", "Invalid redirection URI(s)", HTTPResponse.SC_BAD_REQUEST);


    /**
     * Client registration: The value of one of the client meta data fields
     * is invalid and the server has rejected this request. Note that an
     * authorisation server may choose to substitute a valid value for any
     * requested parameter of a client's meta data.
     */
    public static final ErrorObject INVALID_CLIENT_METADATA =
            new ErrorObject("invalid_client_metadata", "Invalid client metadata field", HTTPResponse.SC_BAD_REQUEST);


    /**
     * Client registration: The software statement presented is invalid.
     */
    public static final ErrorObject INVALID_SOFTWARE_STATEMENT =
            new ErrorObject("invalid_software_statement", "Invalid software statement", HTTPResponse.SC_BAD_REQUEST);


    /**
     * Client registration: The software statement presented is not
     * approved for use by this authorisation server.
     */
    public static final ErrorObject UNAPPROVED_SOFTWARE_STATEMENT =
            new ErrorObject("unapproved_software_statement", "Unapproved software statement", HTTPResponse.SC_BAD_REQUEST);


    /**
     * Prevents public instantiation.
     */
    private RegistrationError() {
    }
}
