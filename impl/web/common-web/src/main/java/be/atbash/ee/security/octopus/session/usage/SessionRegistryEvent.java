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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 *
 */

public class SessionRegistryEvent {

    private String sessionId;
    private HttpSession session;
    private UserAction userAction;
    private UserPrincipal userPrincipal;
    private AuthenticationToken authenticationToken;
    private HttpServletRequest httpServletRequest;

    public SessionRegistryEvent(HttpSession session, UserAction userAction) {
        this.session = session;
        this.userAction = userAction;

        sessionId = session.getId();
    }

    public SessionRegistryEvent(String sessionId, UserPrincipal userPrincipal, AuthenticationToken authenticationToken) {
        this.sessionId = sessionId;
        this.userPrincipal = userPrincipal;
        this.authenticationToken = authenticationToken;
        userAction = UserAction.LOGON;
    }

    public SessionRegistryEvent(String sessionId) {
        this.sessionId = sessionId;
        userAction = UserAction.LOGOUT;
    }

    public SessionRegistryEvent(HttpServletRequest httpServletRequest) {
        this.httpServletRequest = httpServletRequest;
        userAction = UserAction.REMEMBER_ME_LOGON;
    }

    public String getSessionId() {
        return sessionId;
    }

    public HttpSession getSession() {
        return session;
    }

    public UserAction getUserAction() {
        return userAction;
    }

    public UserPrincipal getUserPrincipal() {
        return userPrincipal;
    }

    public AuthenticationToken getAuthenticationToken() {
        return authenticationToken;
    }

    public HttpServletRequest getHttpServletRequest() {
        return httpServletRequest;
    }
}
