/*
 * Copyright 2014-2020 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.util;

import be.atbash.ee.security.octopus.ShiroEquivalent;

import jakarta.servlet.http.HttpServletRequest;
import java.io.Serializable;

/**
 * Maintains request data for a request that was redirected, so that after authentication
 * the user can be redirected to the originally requested page.
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.web.util.SavedRequest"})
public class SavedRequest implements Serializable {

    //TODO - complete JavaDoc

    private String method;
    private String queryString;
    private String requestURI;

    /**
     * Constructs a new instance from the given HTTP request.
     *
     * @param request the current request to save.
     */
    public SavedRequest(HttpServletRequest request) {
        method = request.getMethod();
        queryString = request.getQueryString();
        requestURI = request.getRequestURI();
    }

    public String getMethod() {
        return method;
    }

    public String getQueryString() {
        return queryString;
    }

    public String getRequestURI() {
        return requestURI;
    }

    public String getRequestUrl() {
        StringBuilder requestUrl = new StringBuilder(getRequestURI());
        if (getQueryString() != null) {
            requestUrl.append("?").append(getQueryString());
        }
        return requestUrl.toString();
    }
}
