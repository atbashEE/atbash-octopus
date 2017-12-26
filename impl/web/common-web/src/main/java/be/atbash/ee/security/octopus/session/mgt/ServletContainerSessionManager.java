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
package be.atbash.ee.security.octopus.session.mgt;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.authz.AuthorizationException;
import be.atbash.ee.security.octopus.session.*;

import javax.enterprise.context.ApplicationScoped;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * SessionManager implementation providing {@link Session} implementations that are merely wrappers for the
 * Servlet container's {@link HttpSession}.
 * <p/>
 * Despite its name, this implementation <em>does not</em> itself manage Sessions since the Servlet container
 * provides the actual management support.  This class mainly exists to 'impersonate' a regular Shiro
 * {@code SessionManager} so it can be pluggable into a normal Shiro configuration in a pure web application.
 * <p/>
 * Note that because this implementation relies on the {@link HttpSession HttpSession}, it is only functional in a
 * servlet container - it is not capable of supporting Sessions for any clients other than those using the HTTP
 * protocol.
 * <p/>
 * Therefore, if you need {@code Session} support for heterogeneous clients (e.g. web browsers,
 * RMI clients, etc), use the {@link DefaultWebSessionManager DefaultWebSessionManager}
 * instead.  The {@code DefaultWebSessionManager} supports both traditional web-based access as well as non web-based
 * clients.
 *
 * @see DefaultWebSessionManager
 */
@ApplicationScoped
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.web.session.mgt.ServletContainerSessionManager"})
public class ServletContainerSessionManager implements SessionManager {

    //TODO - complete JavaDoc

    //TODO - read session timeout value from web.xml

    public ServletContainerSessionManager() {
    }

    public Session start(SessionContext context) throws AuthorizationException {
        return createSession(context);
    }

    public Session getSession(SessionKey key) throws SessionException {
        /*
        if (!WebUtils.isHttp(key)) {
            String msg = "SessionKey must be an HTTP compatible implementation.";
            throw new IllegalArgumentException(msg);
        }
        */

        HttpServletRequest request = key.getServletRequest();

        Session session = null;

        HttpSession httpSession = request.getSession(false);
        if (httpSession != null) {
            session = createSession(httpSession, request.getRemoteHost());
        }

        return session;

    }

    /*
    private String getHost(SessionContext context) {
        String host = context.getHost();
        if (host == null) {
            ServletRequest request = WebUtils.getRequest(context);
            if (request != null) {
                host = request.getRemoteHost();
            }
        }
        return host;

    }
    */

    /**
     */
    public Session createSession(SessionContext sessionContext) throws AuthorizationException {

        /*
        if (!WebUtils.isHttp(sessionContext)) {
            String msg = "SessionContext must be an HTTP compatible implementation.";
            throw new IllegalArgumentException(msg);
        }
        */

        HttpServletRequest request = sessionContext.getServletRequest();

        HttpSession httpSession = request.getSession();

        //SHIRO-240: DO NOT use the 'globalSessionTimeout' value here on the acquired session.
        //see: https://issues.apache.org/jira/browse/SHIRO-240

        String host = request.getRemoteHost();

        return createSession(httpSession, host);

    }

    protected Session createSession(HttpSession httpSession, String host) {

        return new HttpServletSession(httpSession, host);

    }

    /**
     * This implementation always delegates to the servlet container for sessions, so this method returns
     * {@code true} always.
     *
     * @return {@code true} always
     */
    @Override
    public boolean isHttpSessionUsageAllowed() {
        return true;
    }

}
