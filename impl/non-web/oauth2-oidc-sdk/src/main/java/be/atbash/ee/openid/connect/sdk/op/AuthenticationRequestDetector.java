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
package be.atbash.ee.openid.connect.sdk.op;


import be.atbash.ee.oauth2.sdk.Scope;
import be.atbash.ee.oauth2.sdk.util.MultivaluedMapUtils;
import be.atbash.ee.openid.connect.sdk.OIDCScopeValue;

import java.util.List;
import java.util.Map;


/**
 * OpenID authentication request detector.
 */
public class AuthenticationRequestDetector {

    /**
     * Returns {@code true} if the specified query parameters are likely
     * for an OpenID authentication request.
     *
     * @param queryParams The query parameters.
     * @return {@code true} for a likely OpenID authentication request,
     * else {@code false}.
     */
    public static boolean isLikelyOpenID(Map<String, List<String>> queryParams) {

        Scope scope = Scope.parse(MultivaluedMapUtils.getFirstValue(queryParams, "scope"));

        if (scope == null) {
            return false;
        }

        return scope.contains(OIDCScopeValue.OPENID);
    }
}
