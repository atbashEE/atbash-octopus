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
     * HTTP Authentication header, equal to <code>WWW-Authenticate</code>
     */
    public static final String AUTHENTICATE_HEADER = "WWW-Authenticate";

    public static final String IDENTITY_REMOVED_KEY = "OCTOPUS_IDENTITY_REMOVED_KEY";

    public static final String SSO_COOKIE_TOKEN = "OCTOPUS_SSO_COOKIE_TOKEN";

    /**
     * Attribute on ServletRequest to define contextRelative flag of RedirectHelper
     */
    public static final String REDIRECT_CONTEXT_RELATIVE = "REDIRECT_CONTEXT_RELATIVE";

    /**
     * Attribute on ServletRequest to define HTTP 1.0  compatible flag of RedirectHelper
     */
    public static final String REDIRECT_HTTP10_COMPATIBLE = "REDIRECT_HTTP10_COMPATIBLE";

    /**
     * Attribute on ServletRequest to indicate the matched chainName (like /pages/**)
     */
    public static final String OCTOPUS_CHAIN_NAME = "octopus.chainName";

    /**
     * Attribute on ServletRequest to indicate the matched chainName (like /pages/**)
     */
    public static final String OCTOPUS_FILTER_NAMES = "octopus.filterNames";
}
