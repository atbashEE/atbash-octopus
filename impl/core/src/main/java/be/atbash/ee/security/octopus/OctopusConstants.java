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
public final class OctopusConstants {

    public static final String INFO_KEY_TOKEN = "token";

    public static final String EMAIL = "email";

    public static final String PICTURE = "picture";
    public static final String GENDER = "gender";
    public static final String LOCALE = "locale";
    public static final String TOKEN = "token";  // FIXME Review usage , same as INFO_KEY_TOKEN
    public static final String UPSTREAM_TOKEN = "upstreamToken";
    public static final String EXTERNAL_SESSION_ID = "externalSession";

    public static final String FIRST_NAME = "firstName";
    public static final String LAST_NAME = "lastName";

    public static final String DOMAIN = "domain";
    public static final String OAUTH2_TOKEN = "OAuth2token"; // FIXME Use INFO_KEY_TOKEN

    /**
     * Attribute name on Servlet request indicating message related to violation of permission,  role, ... . Set by the filters and read by the {@code AccessDeniedHandler}.
     */
    public static final String OCTOPUS_VIOLATION_MESSAGE = "octopus.violation.message";

    public static final String AUTHORIZATION_INFO = "authorizationInfo";

    // FIXME Review usage
    public static final String LOCAL_ID = "localId";
    public static final String EXTERNAL_ID = "externalId";

}
