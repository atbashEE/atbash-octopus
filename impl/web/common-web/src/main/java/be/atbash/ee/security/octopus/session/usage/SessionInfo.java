/*
 * Copyright 2014-2018 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.session.usage;

import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.token.AuthenticationToken;

import javax.servlet.http.HttpSession;

/**
 * Information about 'Sessions' (JSF session but also about Token sessions = lifetime of a token)
 * // TODO Token Session -> Can we integrate this within the Old Shiro Session Concept?
 */

public class SessionInfo {

    private HttpSession httpSession;
    private UserPrincipal userPrincipal;
    private AuthenticationToken authenticationToken;
    private String userAgent;
    private String remoteHost;

    public SessionInfo(HttpSession httpSession, String remoteHost, String userAgent) {
        this.httpSession = httpSession;
        this.remoteHost = remoteHost;
        this.userAgent = userAgent;
    }

    public HttpSession getHttpSession() {
        return httpSession;
    }

    public String getSessionId() {
        return httpSession.getId();
    }

    public String getUserAgent() {
        return userAgent;
    }

    public String getRemoteHost() {
        return remoteHost;
    }

    public UserPrincipal getUserPrincipal() {
        return userPrincipal;
    }

    public void setUserPrincipal(UserPrincipal userPrincipal) {
        this.userPrincipal = userPrincipal;
    }

    public AuthenticationToken getAuthenticationToken() {
        return authenticationToken;
    }

    public void setAuthenticationToken(AuthenticationToken authenticationToken) {
        this.authenticationToken = authenticationToken;
    }

    public boolean isAuthenticated() {
        return userPrincipal != null;
    }

    public String getPrincipalName() {
        String result;
        if (isAuthenticated()) {
            result = userPrincipal.getName();
        } else {
            result = "[anonymous]";
        }
        return result;
    }

    public void clearAuthenticationInfo() {
        userPrincipal = null;
        authenticationToken = null;
    }
}
