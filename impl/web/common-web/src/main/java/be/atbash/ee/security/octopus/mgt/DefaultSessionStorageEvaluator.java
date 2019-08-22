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
package be.atbash.ee.security.octopus.mgt;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.util.WebUtils;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

/**
 * A web-specific {@code SessionStorageEvaluator} that performs the same logic as the parent class
 * {@link DefaultSessionStorageEvaluator} but additionally checks for a request-specific flag that may enable or
 * disable session access.
 * <p/>
 * This implementation usually works in conjunction with the
 * {@link be.atbash.ee.security.octopus.filter.NoSessionCreationFilter}:  If the {@code NoSessionCreationFilter}
 * is configured in a filter chain, that filter will set a specific
 * {@code ServletRequest} {@link javax.servlet.ServletRequest#setAttribute attribute} indicating that session creation
 * should be disabled.
 * <p/>
 * This {@code DefaultSessionStorageEvaluator} will then inspect this attribute, and if it has been set, will return
 * {@code false} from {@link #isSessionStorageEnabled(be.atbash.ee.security.octopus.subject.Subject)} method, thereby preventing
 * Shiro from creating a session for the purpose of storing subject state.
 * <p/>
 * If the request attribute has
 * not been set (i.e. the {@code NoSessionCreationFilter} is not configured or has been disabled), this class does
 * nothing and delegates to the parent class for existing behavior.
 */

@ApplicationScoped
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.mgt.DefaultSessionStorageEvaluator"})
// FIXME Also inclusion of org.apache.shiro.mgt.DefaultWebSessionStorageEvaluator
public class DefaultSessionStorageEvaluator {

    //since 1.2.1
    @Inject
    private WebSecurityManager sessionManager;

    /**
     * Global policy determining if Subject sessions may be used to persist Subject state if the Subject's Session
     * does not yet exist.
     */
    private boolean sessionStorageEnabled = true;

    /**
     * Returns {@code true} if session storage is generally available (as determined by the super class's global
     * configuration property {@link #isSessionStorageEnabled()} and no request-specific override has turned off
     * session storage, {@code false} otherwise.
     * <p/>
     * This means session storage is disabled if the {@link #isSessionStorageEnabled()} property is {@code false} or if
     * a request attribute is discovered that turns off session storage for the current request.
     *
     * @param subject the {@code Subject} for which session state persistence may be enabled
     * @return {@code true} if session storage is generally available (as determined by the super class's global
     * configuration property {@link #isSessionStorageEnabled()} and no request-specific override has turned off
     * session storage, {@code false} otherwise.
     */
    @SuppressWarnings({"SimplifiableIfStatement"})
    public boolean isSessionStorageEnabled(WebSubject subject) {
        if (subject.getSession(false) != null) {
            //use what already exists
            return true;
        }

        if (!isSessionStorageEnabled()) {
            //honor global setting:
            return false;
        }

        //SHIRO-350: non-web subject instances can't be saved to web-only session managers:
        //since 1.2.1:
        /*
        TODO ??
        if (!(subject instanceof WebSubject) && (this.sessionManager != null && !(this.sessionManager instanceof NativeSessionManager))) {
            return false;
        }
        */

        return WebUtils._isSessionCreationEnabled(subject);
    }

    /**
     * Returns {@code true} if any Subject's {@code Session} may be used to persist that {@code Subject}'s state,
     * {@code false} otherwise.  The default value is {@code true}.
     * <p/>
     * <b>N.B.</b> This is a global configuration setting; setting this value to {@code false} will disable sessions
     * to persist Subject state for all Subjects that do not already have a Session.  It should typically only be set
     * to {@code false} for 100% stateless applications (e.g. when sessions aren't used or when remote clients
     * authenticate on every request).
     *
     * @return {@code true} if any Subject's {@code Session} may be used to persist that {@code Subject}'s state,
     * {@code false} otherwise.
     */
    public boolean isSessionStorageEnabled() {
        return sessionStorageEnabled;
    }

    /**
     * Sets if any Subject's {@code Session} may be used to persist that {@code Subject}'s state.  The
     * default value is {@code true}.
     * <p/>
     * <b>N.B.</b> This is a global configuration setting; setting this value to {@code false} will disable sessions
     * to persist Subject state for all Subjects that do not already have a Session.  It should typically only be set
     * to {@code false} for 100% stateless applications (e.g. when sessions aren't used or when remote clients
     * authenticate on every request).
     *
     * @param sessionStorageEnabled if any Subject's {@code Session} may be used to persist that {@code Subject}'s state.
     */
    public void setSessionStorageEnabled(boolean sessionStorageEnabled) {
        this.sessionStorageEnabled = sessionStorageEnabled;
    }

}