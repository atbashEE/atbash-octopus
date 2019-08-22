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
package be.atbash.ee.security.octopus;

import be.atbash.ee.security.octopus.context.ThreadContext;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.ee.security.octopus.subject.SubjectResolver;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.util.PublicAPI;

import java.util.ServiceLoader;

/**
 * Accesses the currently accessible {@code Subject} for the calling code depending on runtime environment.
 * We keep this method to have 'backwards' compatibility with the Shiro Octopus version
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.SecurityUtils"})
@PublicAPI
public abstract class SecurityUtils {

    private static SubjectResolver subjectResolver;

    static {
        subjectResolver = ServiceLoader.load(SubjectResolver.class).iterator().next();
    }

    /**
     * Returns the currently accessible {@code Subject} available to the calling code depending on
     * runtime environment.
     * <p/>
     *
     * @return the currently accessible {@code Subject} accessible to the calling code.
     * @throws IllegalStateException if no {@link Subject Subject} instance or
     *                               {@link SecurityManager SecurityManager} instance is available with which to obtain
     *                               a {@code Subject}, which which is considered an invalid application configuration
     *                               - a Subject should <em>always</em> be available to the caller.
     */
    public static <T extends Subject> T getSubject() {
        return subjectResolver.getSubject();
    }


    /**
     * Can be used to retrieve the <strong>current</strong> User Principal information in case we have
     * multiple Authentication providers.
     * @return
     */
    public static UserPrincipal getIntermediateUserPrincipal() {
        return ThreadContext.getIntermediateUserPrincipal();
    }

}