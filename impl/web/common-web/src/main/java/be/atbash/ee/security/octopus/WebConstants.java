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
package be.atbash.ee.security.octopus;

import be.atbash.util.Reviewed;

/**
 *
 */
@Reviewed
public final class WebConstants {
    /**
     * HTTP Authorization header, equal to <code>Authorization</code>
     */
    public static final String AUTHORIZATION_HEADER = "Authorization";

    /**
     * HTTP Authentication header, equal to <code>WWW-Authenticate</code>
     */
    public static final String AUTHENTICATE_HEADER = "WWW-Authenticate";

    /**
     * HTTP Authorization header value, equal to <code>Bearer</code>
     */
    public static final String BEARER = "Bearer";

    public static final String IDENTITY_REMOVED_KEY = "OCTOPUS_IDENTITY_REMOVED_KEY";

    public static final String X_API_KEY = "x-api-key";

    public static final String SSO_COOKIE_TOKEN = "OCTOPUS_SSO_COOKIE_TOKEN";
}
