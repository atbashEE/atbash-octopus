/*
 * Copyright 2014-2020 Rudy De Busscher (https://www.atbash.be)
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
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.subject.SecurityManager;
import be.atbash.ee.security.octopus.subject.SubjectContext;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.subject.support.WebSubjectContext;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Map;

/**
 * A {@code SubjectFactory} implementation that creates {@link WebDelegatingSubject} instances.
 * <p/>
 * {@code WebDelegatingSubject} instances are required if Request/Response objects are to be maintained across
 * threads when using the {@code Subject} {@link Subject#associateWith(java.util.concurrent.Callable) createCallable}
 * and {@link Subject#associateWith(Runnable) createRunnable} methods.
 */
@ApplicationScoped
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.web.mgt.DefaultWebSubjectFactory", "FIXME Others"})
// FIXME Find out which classes are exactly integrated here.
public class WebSubjectFactory {

    /**
     * Creates a new Subject instance reflecting the state of the specified contextual data.  The data would be
     * anything required to required to construct a {@code Subject} instance and its contents can vary based on
     * environment.
     * <p/>
     * Any data supported by Shiro core will be accessible by one of the {@code SubjectContext}'s {@code get*}
     * or {@code resolve*} methods.  All other data is available as map {@link Map#get attribute}s.
     *
     * @param context the contextual data to be used by the implementation to construct an appropriate {@code Subject}
     *                instance.
     * @return a {@code Subject} instance created based on the specified context.
     * @see SubjectContext
     */
    public WebSubject createSubject(WebSubjectContext context) {

        SecurityManager securityManager = context.resolveSecurityManager();
        Session session = context.resolveSession();
        boolean sessionEnabled = context.isSessionCreationEnabled();
        PrincipalCollection principals = context.resolvePrincipals();
        boolean authenticated = context.resolveAuthenticated();
        boolean remembered = context.isRemembered();
        boolean fromRememberedIdentity = context.isFromRememberedIdentify();
        String host = context.resolveHost();
        HttpServletRequest request = context.resolveServletRequest();
        HttpServletResponse response = context.resolveServletResponse();

        return new WebSubject(principals, authenticated, remembered, fromRememberedIdentity, host, session, sessionEnabled,
                request, response, (WebSecurityManager) securityManager, context.getAuthorizingRealm());
    }

}
