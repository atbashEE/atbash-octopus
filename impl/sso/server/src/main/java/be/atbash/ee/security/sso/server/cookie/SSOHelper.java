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
package be.atbash.ee.security.sso.server.cookie;


import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.util.WebUtils;

import javax.enterprise.context.ApplicationScoped;
import javax.servlet.http.HttpServletRequest;

/**
 *
 */
@ApplicationScoped
public class SSOHelper {

    private static final String CLIENT_ID_LOGIN = "SSOClientIdLogin";

    public void markAsSSOLogin(HttpServletRequest httpServletRequest, String clientId) {
        httpServletRequest.getSession().setAttribute(CLIENT_ID_LOGIN, clientId);
    }

    public String getSSOClientId(WebSubject subject) {
        HttpServletRequest servletRequest = WebUtils.getHttpRequest(subject);
        return getSSOClientId(servletRequest);
    }

    public String getSSOClientId(HttpServletRequest httpRequest) {
        if (WebUtils._isSessionCreationEnabled(httpRequest)) {
            // When the SSO Client ask for User information, the Rest calls has been marked as no session allowed.
            //But the SSOCookieRememberMeManager authenticates the user and thus a on successfull login is performed.
            // and out CookieManager checks if it needs to write a new Cookie.
            return (String) httpRequest.getSession().getAttribute(CLIENT_ID_LOGIN);
        } else {
            return null;
        }
    }
}
