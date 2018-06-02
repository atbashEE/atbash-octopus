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
package be.atbash.ee.security.octopus.subject.support;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.authc.AuthenticationException;
import be.atbash.ee.security.octopus.authz.AuthorizationException;
import be.atbash.ee.security.octopus.authz.UnauthenticatedException;
import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.ee.security.octopus.mgt.DefaultSecurityManager;
import be.atbash.ee.security.octopus.subject.*;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.util.OctopusCollectionUtils;
import be.atbash.util.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * Implementation of the {@code Subject} interface that delegates
 * method calls to an underlying {@link org.apache.shiro.mgt.SecurityManager SecurityManager} instance for security checks.
 * It is essentially a {@code SecurityManager} proxy.
 * <p/>
 * This implementation does not maintain state such as roles and permissions (only {@code Subject}
 * {@link #getPrincipals() principals}, such as usernames or user primary keys) for better performance in a stateless
 * architecture.  It instead asks the underlying {@code SecurityManager} every time to perform
 * the authorization check.
 * <p/>
 * A common misconception in using this implementation is that an EIS resource (RDBMS, etc) would
 * be &quot;hit&quot; every time a method is called.  This is not necessarily the case and is
 * up to the implementation of the underlying {@code SecurityManager} instance.  If caching of authorization
 * data is desired (to eliminate EIS round trips and therefore improve database performance), it is considered
 * much more elegant to let the underlying {@code SecurityManager} implementation or its delegate components
 * manage caching, not this class.  A {@code SecurityManager} is considered a business-tier component,
 * where caching strategies are better managed.
 * <p/>
 * Applications from large and clustered to simple and JVM-local all benefit from
 * stateless architectures.  This implementation plays a part in the stateless programming
 * paradigm and should be used whenever possible.
 */
@ShiroEquivalent(shiroClassNames = "org.apache.shiro.subject.support.DelegatingSubject")
public class DelegatingSubject implements Subject {

    private static final Logger log = LoggerFactory.getLogger(DelegatingSubject.class);

    private static final String RUN_AS_PRINCIPALS_SESSION_KEY =
            DelegatingSubject.class.getName() + ".RUN_AS_PRINCIPALS_SESSION_KEY";

    protected PrincipalCollection principals;
    protected boolean authenticated;

    protected transient DefaultSecurityManager securityManager;

    public DelegatingSubject(DefaultSecurityManager securityManager) {
        this(null, false, securityManager);
    }

    public DelegatingSubject(PrincipalCollection principals, boolean authenticated, DefaultSecurityManager securityManager) {
        if (securityManager == null) {
            throw new IllegalArgumentException("SecurityManager argument cannot be null.");
        }
        this.securityManager = securityManager;
        this.principals = principals;
        this.authenticated = authenticated;
    }

    protected boolean hasPrincipals() {
        return !OctopusCollectionUtils.isEmpty(getPrincipals());
    }

    private UserPrincipal getPrimaryPrincipal(PrincipalCollection principals) {
        if (!OctopusCollectionUtils.isEmpty(principals)) {
            return principals.getPrimaryPrincipal();
        }
        return null;
    }

    /**
     * @see Subject#getPrincipal()
     */
    public UserPrincipal getPrincipal() {
        return getPrimaryPrincipal(getPrincipals());
    }

    public PrincipalCollection getPrincipals() {
        List<PrincipalCollection> runAsPrincipals = getRunAsPrincipalsStack();
        return CollectionUtils.isEmpty(runAsPrincipals) ? this.principals : runAsPrincipals.get(0);
    }

    public boolean isPermitted(String permission) {
        return hasPrincipals() && securityManager.isPermitted(getPrincipals(), permission);
    }

    public boolean isPermitted(Permission permission) {
        return hasPrincipals() && securityManager.isPermitted(getPrincipals(), permission);
    }

    public boolean[] isPermitted(String... permissions) {
        if (hasPrincipals()) {
            return securityManager.isPermitted(getPrincipals(), permissions);
        } else {
            return new boolean[permissions.length];
        }
    }

    public boolean[] isPermitted(List<Permission> permissions) {
        if (hasPrincipals()) {
            return securityManager.isPermitted(getPrincipals(), permissions);
        } else {
            return new boolean[permissions.size()];
        }
    }

    public boolean isPermittedAll(String... permissions) {
        return hasPrincipals() && securityManager.isPermittedAll(getPrincipals(), permissions);
    }

    public boolean isPermittedAll(Collection<Permission> permissions) {
        return hasPrincipals() && securityManager.isPermittedAll(getPrincipals(), permissions);
    }

    protected void assertAuthzCheckPossible() throws AuthorizationException {
        if (!hasPrincipals()) {
            String msg = "This subject is anonymous - it does not have any identifying principals and " +
                    "authorization operations require an identity to check against.  A Subject instance will " +
                    "acquire these identifying principals automatically after a successful login is performed " +
                    "be executing " + Subject.class.getName() + ".login(AuthenticationToken) or when 'Remember Me' " +
                    "functionality is enabled by the SecurityManager.  This exception can also occur when a " +
                    "previously logged-in Subject has logged out which " +
                    "makes it anonymous again.  Because an identity is currently not known due to any of these " +
                    "conditions, authorization is denied.";
            throw new UnauthenticatedException(msg);
        }
    }

    public void checkPermission(String permission) throws AuthorizationException {
        assertAuthzCheckPossible();
        securityManager.checkPermission(getPrincipals(), permission);
    }

    public void checkPermission(Permission permission) throws AuthorizationException {
        assertAuthzCheckPossible();
        securityManager.checkPermission(getPrincipals(), permission);
    }

    public void checkPermissions(String... permissions) throws AuthorizationException {
        assertAuthzCheckPossible();
        securityManager.checkPermissions(getPrincipals(), permissions);
    }

    public void checkPermissions(Collection<Permission> permissions) throws AuthorizationException {
        assertAuthzCheckPossible();
        securityManager.checkPermissions(getPrincipals(), permissions);
    }

    public boolean hasRole(String roleIdentifier) {
        return hasPrincipals() && securityManager.hasRole(getPrincipals(), roleIdentifier);
    }

    public boolean[] hasRoles(List<String> roleIdentifiers) {
        if (hasPrincipals()) {
            return securityManager.hasRoles(getPrincipals(), roleIdentifiers);
        } else {
            return new boolean[roleIdentifiers.size()];
        }
    }

    public boolean hasAllRoles(Collection<String> roleIdentifiers) {
        return hasPrincipals() && securityManager.hasAllRoles(getPrincipals(), roleIdentifiers);
    }

    public void checkRole(String role) throws AuthorizationException {
        assertAuthzCheckPossible();
        securityManager.checkRole(getPrincipals(), role);
    }

    public void checkRoles(String... roleIdentifiers) throws AuthorizationException {
        assertAuthzCheckPossible();
        securityManager.checkRoles(getPrincipals(), roleIdentifiers);
    }

    public void checkRoles(Collection<String> roles) throws AuthorizationException {
        assertAuthzCheckPossible();
        securityManager.checkRoles(getPrincipals(), roles);
    }

    public void login(AuthenticationToken token) throws AuthenticationException {
        Subject subject = securityManager.login(this, token);

        PrincipalCollection principals;

        principals = subject.getPrincipals();

        if (principals == null || principals.isEmpty()) {
            String msg = "Principals returned from securityManager.login( token ) returned a null or " +
                    "empty value.  This value must be non null and populated with one or more elements.";
            throw new IllegalStateException(msg);
        }
        this.principals = principals;
        this.authenticated = true;
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    public boolean isRemembered() {
        return false; // Never remembered in SE in the sense
    }

    public void logout() {
        try {
            this.securityManager.logout(this);
        } finally {
            this.principals = null;
            this.authenticated = false;
            //Don't set securityManager to null here - the Subject can still be
            //used, it is just considered anonymous at this point.  The SecurityManager instance is
            //necessary if the subject would log in again or acquire a new session.  This is in response to
            //https://issues.apache.org/jira/browse/JSEC-22
            //this.securityManager = null;
        }
    }

    public <V> V execute(Callable<V> callable) throws ExecutionException {
        Callable<V> associated = associateWith(callable);
        try {
            return associated.call();
        } catch (Throwable t) {
            throw new ExecutionException(t);
        }
    }

    public void execute(Runnable runnable) {
        Runnable associated = associateWith(runnable);
        associated.run();
    }

    public <V> Callable<V> associateWith(Callable<V> callable) {
        return new SubjectCallable<>(this, callable);
    }

    public Runnable associateWith(Runnable runnable) {
        if (runnable instanceof Thread) {
            String msg = "This implementation does not support Thread arguments because of JDK ThreadLocal " +
                    "inheritance mechanisms required by Shiro.  Instead, the method argument should be a non-Thread " +
                    "Runnable and the return value from this method can then be given to an ExecutorService or " +
                    "another Thread.";
            throw new UnsupportedOperationException(msg);
        }
        return new SubjectRunnable(this, runnable);
    }

    // ======================================
    // 'Run As' support implementations
    // ======================================

    public void runAs(PrincipalCollection principals) {
        if (!hasPrincipals()) {
            String msg = "This subject does not yet have an identity.  Assuming the identity of another " +
                    "Subject is only allowed for Subjects with an existing identity.  Try logging this subject in " +
                    "first, or using the " + SubjectBuilder.class.getName() + " to build ad hoc Subject instances " +
                    "with identities as necessary.";
            throw new IllegalStateException(msg);
        }
        pushIdentity(principals);
    }

    public boolean isRunAs() {
        List<PrincipalCollection> stack = getRunAsPrincipalsStack();
        return !CollectionUtils.isEmpty(stack);
    }

    public PrincipalCollection getPreviousPrincipals() {
        PrincipalCollection previousPrincipals = null;
        List<PrincipalCollection> stack = getRunAsPrincipalsStack();
        int stackSize = stack != null ? stack.size() : 0;
        if (stackSize > 0) {
            if (stackSize == 1) {
                previousPrincipals = this.principals;
            } else {
                //always get the one behind the current:
                assert stack != null;
                previousPrincipals = stack.get(1);
            }
        }
        return previousPrincipals;
    }

    public PrincipalCollection releaseRunAs() {
        return popIdentity();
    }

    @SuppressWarnings("unchecked")
    private List<PrincipalCollection> getRunAsPrincipalsStack() {
        return null;
    }

    private void clearRunAsIdentities() {
        throw new UnsupportedOperationException("Need to implement be.atbash.ee.security.octopus.subject.support.DelegatingSubject.clearRunAsIdentities");
        /*
        Session session = getSession(false);
        if (session != null) {
            session.removeAttribute(RUN_AS_PRINCIPALS_SESSION_KEY);
        }
        */
    }

    private void pushIdentity(PrincipalCollection principals) throws NullPointerException {
        throw new UnsupportedOperationException("Need to implement be.atbash.ee.security.octopus.subject.support.DelegatingSubject.pushIdentity");
        /*
        if (CollectionUtils.isEmpty(principals)) {
            String msg = "Specified Subject principals cannot be null or empty for 'run as' functionality.";
            throw new NullPointerException(msg);
        }
        List<PrincipalCollection> stack = getRunAsPrincipalsStack();
        if (stack == null) {
            stack = new CopyOnWriteArrayList<PrincipalCollection>();
        }
        stack.add(0, principals);
        Session session = getSession();
        session.setAttribute(RUN_AS_PRINCIPALS_SESSION_KEY, stack);
        */
    }

    private PrincipalCollection popIdentity() {
        throw new UnsupportedOperationException("Need to implement be.atbash.ee.security.octopus.subject.support.DelegatingSubject.popIdentity");
        /*
        PrincipalCollection popped = null;

        List<PrincipalCollection> stack = getRunAsPrincipalsStack();
        if (!CollectionUtils.isEmpty(stack)) {
            popped = stack.remove(0);
            Session session;
            if (!CollectionUtils.isEmpty(stack)) {
                //persist the changed stack to the session
                session = getSession();
                session.setAttribute(RUN_AS_PRINCIPALS_SESSION_KEY, stack);
            } else {
                //stack is empty, remove it from the session:
                clearRunAsIdentities();
            }
        }

        return popped;
        */
    }
}
