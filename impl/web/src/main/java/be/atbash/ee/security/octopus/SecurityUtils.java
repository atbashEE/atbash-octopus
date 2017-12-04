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
package be.atbash.ee.security.octopus;


import be.atbash.ee.security.octopus.mgt.WebSecurityManager;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.util.ThreadContext;
import org.apache.deltaspike.core.api.provider.BeanProvider;

/**
 * Accesses the currently accessible {@code Subject} for the calling code depending on runtime environment.
 *
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.SecurityUtils"})
public abstract class SecurityUtils {

    /**
     * Returns the currently accessible {@code Subject} available to the calling code depending on
     * runtime environment.
     * <p/>
     * This method is provided as a way of obtaining a {@code Subject} without having to resort to
     * implementation-specific methods.  It also allows the Shiro team to change the underlying implementation of
     * this method in the future depending on requirements/updates without affecting your code that uses it.
     *
     * @return the currently accessible {@code Subject} accessible to the calling code.
     * @throws IllegalStateException if no {@link Subject Subject} instance or
     *                               {@link SecurityManager SecurityManager} instance is available with which to obtain
     *                               a {@code Subject}, which which is considered an invalid application configuration
     *                               - a Subject should <em>always</em> be available to the caller.
     */
    public static WebSubject getSubject() {
        WebSubject subject = ThreadContext.getSubject();
        if (subject == null) {
            throw new UnsupportedOperationException("Not implemented be.atbash.ee.security.octopus.SecurityUtils.getSubject");
            //subject = (new Subject.Builder()).buildSubject();
            //ThreadContext.bind(subject);
        }
        return subject;
    }

    /**
     * Returns the SecurityManager accessible to the calling code.
     * <p/>
     * This implementation favors acquiring a thread-bound {@code SecurityManager} if it can find one.  If one is
     * not available to the executing thread, it will attempt to use the static singleton if available (see the
     * {@link #setSecurityManager setSecurityManager} method for more on the static singleton).
     * <p/>
     * If neither the thread-local or static singleton instances are available, this method throws an
     * {@code UnavailableSecurityManagerException} to indicate an error - a SecurityManager should always be accessible
     * to calling code in an application. If it is not, it is likely due to a Shiro configuration problem.
     *
     * @return the SecurityManager accessible to the calling code.
     * @throws UnavailableSecurityManagerException if there is no {@code SecurityManager} instance available to the
     *                                             calling code, which typically indicates an invalid application configuration.
     */
    public static WebSecurityManager getSecurityManager() {
        // FIXME EE7 CDI usage, no bean Manager
        return BeanProvider.getContextualReference(WebSecurityManager.class);
    }
}
