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

    /**
     * Defines the specified UserAction (LogOn, LogOut, ...) for that Session
     *
     * @param session    The HttpSession the user has when UserAction is performed
     * @param userAction The UserAction (LogOn, LogOut, ...) which is performed
     */
    public SessionRegistryEvent(HttpSession session, UserAction userAction) {
        this.session = session;
        this.userAction = userAction;

        sessionId = session.getId();
    }

    /**
     * Performs a LogOn for the sessionId for the user (identified by UserPrincipal and AuthenticationToken which is sued for the logon)
     * @param sessionId the sessionId the user has when UserAction is performed
     * @param userPrincipal UserPrincipal identifying the user.
     * @param authenticationToken AuthenticationToken used for the authentication for logon.
     */
    public SessionRegistryEvent(String sessionId, UserPrincipal userPrincipal, AuthenticationToken authenticationToken) {
        this.sessionId = sessionId;
        this.userPrincipal = userPrincipal;
        this.authenticationToken = authenticationToken;
        userAction = UserAction.LOGON;
    }

    /**
     * Defines a LogOut of the session.
     * @param sessionId the sessionId from the session who has logged out.
     */
    public SessionRegistryEvent(String sessionId) {
        this.sessionId = sessionId;
        userAction = UserAction.LOGOUT;
    }

    public SessionRegistryEvent(HttpServletRequest httpServletRequest, UserPrincipal userPrincipal) {
        this.httpServletRequest = httpServletRequest;
        this.userPrincipal = userPrincipal;
        userAction = UserAction.REMEMBER_ME_LOGON;
    }

    public String getSessionId() {
        return sessionId == null ? httpServletRequest.getSession().getId() : sessionId;
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
