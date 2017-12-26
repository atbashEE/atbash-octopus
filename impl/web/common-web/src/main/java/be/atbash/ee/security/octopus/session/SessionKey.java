/*
 * Copyright 2014-2017 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.session;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.util.RequestPairSource;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.Serializable;

/**
 * A {@code SessionKey} is a key that allows look-up of any particular {@link org.apache.shiro.session.Session Session}
 * instance.  This is not to be confused what is probably better recognized as a session <em>attribute</em> key - a key
 * that is used to acquire a session attribute via the
 * {@link org.apache.shiro.session.Session#getAttribute(Object) Session.getAttribute} method.  A {@code SessionKey}
 * looks up a Session object directly.
 * <p/>
 * While a {@code SessionKey} allows lookup of <em>any</em> Session that might exist, this is not something in practice
 * done too often by most Shiro end-users.  Instead, it is usually more convenient to acquire the currently executing
 * {@code Subject}'s session via the {@link org.apache.shiro.subject.Subject#getSession} method.  This interface and
 * its usages are best suited for framework development.
 */
@ShiroEquivalent(shiroClassNames = "org.apache.shiro.session.mgt.SessionKey")
public class SessionKey implements RequestPairSource {

    private HttpServletRequest servletRequest;
    private HttpServletResponse servletResponse;

    public SessionKey(HttpServletRequest request, HttpServletResponse response) {
        if (request == null) {
            throw new NullPointerException("request argument cannot be null.");
        }
        if (response == null) {
            throw new NullPointerException("response argument cannot be null.");
        }
        servletRequest = request;
        servletResponse = response;
    }

    public SessionKey(Serializable sessionId, HttpServletRequest request, HttpServletResponse response) {
        this(request, response);
        setSessionId(sessionId);
    }

    public SessionKey(Serializable sessionId) {
        setSessionId(sessionId);
    }

    private Serializable sessionId;

    public void setSessionId(Serializable sessionId) {
        this.sessionId = sessionId;
    }

    public Serializable getSessionId() {
        return sessionId;
    }

    public HttpServletRequest getServletRequest() {
        return servletRequest;
    }

    public HttpServletResponse getServletResponse() {
        return servletResponse;
    }
}
