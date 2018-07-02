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
package be.atbash.ee.security.octopus.mgt;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.session.Session;
import be.atbash.ee.security.octopus.session.SessionException;
import be.atbash.ee.security.octopus.session.SessionKey;
import be.atbash.ee.security.octopus.session.mgt.ServletContainerSessionManager;
import be.atbash.ee.security.octopus.subject.SecurityManager;

/**
 * Shiro support of a {@link SecurityManager} class hierarchy that delegates all
 * {@link org.apache.shiro.session.Session session} operations to a wrapped
 * {@link org.apache.shiro.session.mgt.SessionManager SessionManager} instance.  That is, this class implements the
 * methods in the {@link SessionManager SessionManager} interface, but in reality, those methods are merely
 * passthrough calls to the underlying 'real' {@code SessionManager} instance.
 * <p/>
 * The remaining {@code SecurityManager} methods not implemented by this class or its parents are left to be
 * implemented by subclasses.
 * <p/>
 * In keeping with the other classes in this hierarchy and Shiro's desire to minimize configuration whenever
 * possible, suitable default instances for all dependencies will be created upon instantiation.
 */
@ShiroEquivalent(shiroClassNames = "org.apache.shiro.mgt.SessionsSecurityManager")
public abstract class SessionsSecurityManager implements SecurityManager {

    /**
     * The internal delegate <code>SessionManager</code> used by this security manager that manages all the
     * application's {@link Session Session}s.
     */
    private ServletContainerSessionManager sessionManager;

    /**
     * Default no-arg constructor, internally creates a suitable default {@link SessionManager SessionManager} delegate
     * instance.
     */
    public SessionsSecurityManager() {
        super();
        sessionManager = new ServletContainerSessionManager();
        applyCacheManagerToSessionManager();
    }

    protected void afterSessionManagerSet() {
        applyCacheManagerToSessionManager();
        applyEventBusToSessionManager();
    }

    /**
     * Calls {@link org.apache.shiro.mgt.AuthorizingSecurityManager#afterCacheManagerSet() super.afterCacheManagerSet()} and then immediately calls
     * {@link #applyCacheManagerToSessionManager() applyCacheManagerToSessionManager()} to ensure the
     * <code>CacheManager</code> is applied to the SessionManager as necessary.
     */
    protected void afterCacheManagerSet() {
        applyCacheManagerToSessionManager();
    }

    /**
     * Ensures the internal delegate <code>SessionManager</code> is injected with the newly set
     * {@link #setCacheManager CacheManager} so it may use it for its internal caching needs.
     * <p/>
     * Note:  This implementation only injects the CacheManager into the SessionManager if the SessionManager
     * instance implements the {@link CacheManagerAware CacheManagerAware} interface.
     */
    protected void applyCacheManagerToSessionManager() {
        /*
        FIXME TODO ?? Maybe in SE, not in Web
        if (this.sessionManager instanceof CacheManagerAware) {
            ((CacheManagerAware) this.sessionManager).setCacheManager(getCacheManager());
        }
        */
    }

    /**
     * Ensures the internal delegate <code>SessionManager</code> is injected with the newly set
     * {@link #setEventBus EventBus} so it may use it for its internal event needs.
     * <p/>
     * Note: This implementation only injects the EventBus into the SessionManager if the SessionManager
     * instance implements the {@link EventBusAware EventBusAware} interface.
     */
    protected void applyEventBusToSessionManager() {

        /*
        // FIXME What is the use case for this?
        EventBus eventBus = getEventBus();
        if (eventBus != null && this.sessionManager instanceof EventBusAware) {
            ((EventBusAware)this.sessionManager).setEventBus(eventBus);
        }
        */
    }

    /*
    public Session start(SessionContext context) throws AuthorizationException {
        return this.sessionManager.start(context);
    }
    */

    public Session getSession(SessionKey key) throws SessionException {
        return sessionManager.getSession(key);
    }
/*
    public void destroy() {
        LifecycleUtils.destroy(getSessionManager());
        this.sessionManager = null;
        super.destroy();
    }
    */
}
