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

/**
 * A SessionManager manages the creation, maintenance, and clean-up of all application
 * {@link org.apache.shiro.session.Session Session}s.
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.session.mgt.SessionManager"})
public interface SessionManager {

    /**
     * Starts a new session based on the specified contextual initialization data, which can be used by the underlying
     * implementation to determine how exactly to create the internal Session instance.
     * <p/>
     * This method is mainly used in framework development, as the implementation will often relay the argument
     * to an underlying {@link SessionFactory} which could use the context to construct the internal Session
     * instance in a specific manner.  This allows pluggable {@link org.apache.shiro.session.Session Session} creation
     * logic by simply injecting a {@code SessionFactory} into the {@code SessionManager} instance.
     *
     * @param context the contextual initialization data that can be used by the implementation or underlying
     *                {@link SessionFactory} when instantiating the internal {@code Session} instance.
     * @return the newly created session.
     * @see SessionFactory#createSession(SessionContext)
     */
    Session start(SessionContext context);

    /**
     * Retrieves the session corresponding to the specified contextual data (such as a session ID if applicable), or
     * {@code null} if no Session could be found.  If a session is found but invalid (stopped or expired), a
     * {@link SessionException} will be thrown.
     *
     * @param key the Session key to use to look-up the Session
     * @return the {@code Session} instance corresponding to the given lookup key or {@code null} if no session
     * could be acquired.
     * @throws SessionException if a session was found but it was invalid (stopped/expired).
     */
    Session getSession(SessionKey key) throws SessionException;

    boolean isHttpSessionUsageAllowed();
}