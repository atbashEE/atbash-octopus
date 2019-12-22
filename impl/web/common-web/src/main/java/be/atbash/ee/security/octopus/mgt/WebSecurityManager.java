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
import be.atbash.ee.security.octopus.authc.AfterSuccessfulLoginHandler;
import be.atbash.ee.security.octopus.authc.AuthenticationException;
import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authc.Authenticator;
import be.atbash.ee.security.octopus.authc.event.RememberMeLogonEvent;
import be.atbash.ee.security.octopus.authz.AuthorizationException;
import be.atbash.ee.security.octopus.authz.Authorizer;
import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.ee.security.octopus.realm.OctopusRealm;
import be.atbash.ee.security.octopus.realm.remember.RememberMeManager;
import be.atbash.ee.security.octopus.realm.remember.RememberMeManagerProvider;
import be.atbash.ee.security.octopus.session.InvalidSessionException;
import be.atbash.ee.security.octopus.session.Session;
import be.atbash.ee.security.octopus.session.SessionContext;
import be.atbash.ee.security.octopus.session.SessionKey;
import be.atbash.ee.security.octopus.session.mgt.ServletContainerSessionManager;
import be.atbash.ee.security.octopus.subject.SecurityManager;
import be.atbash.ee.security.octopus.subject.*;
import be.atbash.ee.security.octopus.subject.support.WebSubjectContext;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.OTPToken;
import be.atbash.ee.security.octopus.token.RememberMeAuthenticationToken;
import be.atbash.ee.security.octopus.twostep.TwoStepManager;
import be.atbash.ee.security.octopus.util.OctopusCollectionUtils;
import be.atbash.util.CDIUtils;
import be.atbash.util.exception.AtbashIllegalActionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Event;
import javax.inject.Inject;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.Serializable;
import java.util.Collection;
import java.util.List;

import static be.atbash.ee.security.octopus.WebConstants.IDENTITY_REMOVED_KEY;

/**
 * This interface represents a {@link SecurityManager} implementation that can used in web-enabled applications.
 */
@ApplicationScoped
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.web.mgt.WebSecurityManager"})
public class WebSecurityManager extends SessionsSecurityManager implements Authorizer {

    private Logger log = LoggerFactory.getLogger(WebSecurityManager.class);

    @Inject
    protected DefaultSubjectDAO subjectDAO;

    @Inject
    protected WebSubjectFactory webSubjectFactory;

    @Inject
    private OctopusRealm octopusRealm;

    @Inject
    private RememberMeManagerProvider rememberMeManagerProvider;
    // FIXME this gives issue when adding JSF8 and Rest module because they each have their provider?

    @Inject
    private ServletContainerSessionManager servletContainerSessionManager;

    @Inject
    private TwoStepManager twoStepManager;

    @Inject
    private Event<RememberMeLogonEvent> rememberMeLogonEvent;

    @Override
    public boolean isPermitted(PrincipalCollection principals, String permission) {
        return octopusRealm.isPermitted(principals, permission);
    }

    @Override
    public boolean isPermitted(PrincipalCollection subjectPrincipal, Permission permission) {
        return octopusRealm.isPermitted(subjectPrincipal, permission);
    }

    @Override
    public boolean[] isPermitted(PrincipalCollection subjectPrincipal, String... permissions) {
        return octopusRealm.isPermitted(subjectPrincipal, permissions);
    }

    @Override
    public boolean[] isPermitted(PrincipalCollection subjectPrincipal, List<Permission> permissions) {
        return octopusRealm.isPermitted(subjectPrincipal, permissions);
    }

    @Override
    public boolean isPermittedAll(PrincipalCollection subjectPrincipal, String... permissions) {
        return octopusRealm.isPermittedAll(subjectPrincipal, permissions);
    }

    @Override
    public boolean isPermittedAll(PrincipalCollection subjectPrincipal, Collection<Permission> permissions) {
        return octopusRealm.isPermittedAll(subjectPrincipal, permissions);
    }

    @Override
    public void checkPermission(PrincipalCollection subjectPrincipal, String permission) throws AuthorizationException {
        octopusRealm.checkPermission(subjectPrincipal, permission);
    }

    @Override
    public void checkPermission(PrincipalCollection subjectPrincipal, Permission permission) throws AuthorizationException {
        octopusRealm.checkPermission(subjectPrincipal, permission);
    }

    @Override
    public void checkPermissions(PrincipalCollection subjectPrincipal, String... permissions) throws AuthorizationException {
        octopusRealm.checkPermissions(subjectPrincipal, permissions);
    }

    @Override
    public void checkPermissions(PrincipalCollection subjectPrincipal, Collection<Permission> permissions) throws AuthorizationException {
        octopusRealm.checkPermissions(subjectPrincipal, permissions);
    }

    @Override
    public boolean hasRole(PrincipalCollection subjectPrincipal, String roleIdentifier) {
        return octopusRealm.hasRole(subjectPrincipal, roleIdentifier);
    }

    @Override
    public boolean[] hasRoles(PrincipalCollection subjectPrincipal, List<String> roleIdentifiers) {
        return octopusRealm.hasRoles(subjectPrincipal, roleIdentifiers);
    }

    @Override
    public boolean hasAllRoles(PrincipalCollection subjectPrincipal, Collection<String> roleIdentifiers) {
        return octopusRealm.hasAllRoles(subjectPrincipal, roleIdentifiers);
    }

    @Override
    public void checkRole(PrincipalCollection subjectPrincipal, String roleIdentifier) throws AuthorizationException {
        octopusRealm.checkRole(subjectPrincipal, roleIdentifier);
    }

    @Override
    public void checkRoles(PrincipalCollection subjectPrincipal, Collection<String> roleIdentifiers) throws AuthorizationException {
        octopusRealm.checkRoles(subjectPrincipal, roleIdentifiers);
    }

    @Override
    public void checkRoles(PrincipalCollection subjectPrincipal, String... roleIdentifiers) throws AuthorizationException {
        octopusRealm.checkRoles(subjectPrincipal, roleIdentifiers);
    }

    /**
     * This implementation functions as follows:
     * <p/>
     * <ol>
     * <li>Ensures the {@code SubjectContext} is as populated as it can be, using heuristics to acquire
     * data that may not have already been available to it (such as a referenced session or remembered principals).</li>
     * <li>Calls {@link #doCreateSubject(SubjectContext)} to actually perform the
     * {@code Subject} instance creation.</li>
     * <li>calls {@link #save(Subject) save(subject)} to ensure the constructed
     * {@code Subject}'s state is accessible for future requests/invocations if necessary.</li>
     * <li>returns the constructed {@code Subject} instance.</li>
     * </ol>
     *
     * @param subjectContext any data needed to direct how the Subject should be constructed.
     * @return the {@code Subject} instance reflecting the specified contextual data.
     * @see #ensureSecurityManager(SubjectContext)
     * @see #resolveSession(SubjectContext)
     * @see #resolvePrincipals(SubjectContext)
     * @see #doCreateSubject(SubjectContext)
     * @see #save(Subject)
     */
    public WebSubject createSubject(SubjectContext subjectContext) {
        //create a copy so we don't modify the argument's backing map:
        WebSubjectContext context = copy(subjectContext);

        //Resolve an associated Session (usually based on a referenced session ID), and place it in the context before
        //sending to the SubjectFactory.  The SubjectFactory should not need to know how to acquire sessions as the
        //process is often environment specific - better to shield the SF from these details:
        context = resolveSession(context);

        //Similarly, the SubjectFactory should not require any concept of RememberMe - translate that here first
        //if possible before handing off to the SubjectFactory:
        context = resolvePrincipals(context);

        WebSubject subject = doCreateSubject(context);

        //save this subject for future reference if necessary:
        //(this is needed here in case rememberMe principals were resolved and they need to be stored in the
        //session, so we don't constantly rehydrate the rememberMe PrincipalCollection on every operation).
        //Added in 1.2:

        save(subject);

        return subject;
    }

    /**
     * Creates a {@code Subject} instance for the user represented by the given method arguments.
     *
     * @param token    the {@code AuthenticationToken} submitted for the successful authentication.
     * @param info     the {@code AuthenticationInfo} of a newly authenticated user.
     * @param existing the existing {@code Subject} instance that initiated the authentication attempt
     * @param authenticated authenticated false in case when 2step authentication is required.
     * @param remembered defines if the rememberMe flag was set.
     * @return the {@code Subject} instance that represents the context and session data for the newly
     * authenticated subject.
     */
    protected WebSubject createSubject(AuthenticationToken token, AuthenticationInfo info, WebSubject existing, boolean authenticated, boolean remembered) {
        WebSubjectContext context = new WebSubjectContext(octopusRealm);
        context.setAuthenticated(authenticated);
        context.setRemembered(remembered);
        context.setAuthenticationToken(token);
        context.setAuthenticationInfo(info);
        if (existing != null) {
            context.setSubject(existing);
            context.setServletRequest(existing.getServletRequest());
            context.setServletResponse(existing.getServletResponse());
        }
        return createSubject(context);
    }

    protected WebSubjectContext copy(SubjectContext subjectContext) {
        return new WebSubjectContext(subjectContext);
    }

    /**
     * Attempts to resolve any associated session based on the context and returns a
     * context that represents this resolved {@code Session} to ensure it may be referenced if necessary by the
     * invoked {@link WebSubjectFactory} that performs actual {@link Subject} construction.
     * <p/>
     * If there is a {@code Session} already in the context because that is what the caller wants to be used for
     * {@code Subject} construction, or if no session is resolved, this method effectively does nothing
     * returns the context method argument unaltered.
     *
     * @param context the subject context data that may resolve a Session instance.
     * @return The context to use to pass to a {@link WebSubjectFactory} for subject creation.
     */
    protected WebSubjectContext resolveSession(WebSubjectContext context) {
        if (context.resolveSession() != null) {
            log.debug("Context already contains a session.  Returning.");
            return context;
        }
        try {
            //Context couldn't resolve it directly, let's see if we can since we have direct access to
            //the session manager:
            Session session = resolveContextSession(context);
            if (session != null) {
                context.setSession(session);
            }
        } catch (InvalidSessionException e) {
            log.debug("Resolved SubjectContext context session is invalid.  Ignoring and creating an anonymous " +
                    "(session-less) Subject instance.", e);
        }
        return context;
    }

    protected Session resolveContextSession(WebSubjectContext context) throws InvalidSessionException {

        SessionKey key = getSessionKey(context);
        if (key != null) {
            return getSession(key);
        }
        return servletContainerSessionManager.getSession(key);

    }

    protected SessionKey getSessionKey(WebSubjectContext context) {
        Serializable sessionId = context.getSessionId();
        HttpServletRequest request = context.getServletRequest();
        HttpServletResponse response = context.getServletResponse();
        return new SessionKey(sessionId, request, response);

    }

    /**
     * Attempts to resolve an identity (a {@link PrincipalCollection}) for the context using heuristics.  This
     * implementation functions as follows:
     * <ol>
     * <li>Check the context to see if it can already {@link SubjectContext#resolvePrincipals resolve an identity}.  If
     * so, this method does nothing and returns the method argument unaltered.</li>
     * <li>Check for a RememberMe identity by calling {@link #getRememberedIdentity}.  If that method returns a
     * non-null value, place the remembered {@link PrincipalCollection} in the context.</li>
     * </ol>
     *
     * @param context the subject context data that may provide (directly or indirectly through one of its values) a
     *                {@link PrincipalCollection} identity.
     * @return The Subject context to use to pass to a {@link WebSubjectFactory} for subject creation.
     */
    protected WebSubjectContext resolvePrincipals(WebSubjectContext context) {

        PrincipalCollection principals = context.resolvePrincipals();

        if (OctopusCollectionUtils.isEmpty(principals)) {
            log.trace("No identity (PrincipalCollection) found in the context.  Looking for a remembered identity.");

            principals = getRememberedIdentity(context);

            if (!OctopusCollectionUtils.isEmpty(principals)) {
                log.debug("Found remembered PrincipalCollection.  Adding to the context to be used " +
                        "for subject construction by the SubjectFactory.");

                context.setPrincipals(principals);
                context.setFromRememberedIdentify();

                // The following call was removed (commented out) in Shiro 1.2 because it uses the session as an
                // implementation strategy.  Session use for Shiro's own needs should be controlled in a single place
                // to be more manageable for end-users: there are a number of stateless (e.g. REST) applications that
                // use Shiro that need to ensure that sessions are only used when desirable.  If Shiro's internal
                // implementations used Subject sessions (setting attributes) whenever we wanted, it would be much
                // harder for end-users to control when/where that occurs.
                //
                // Because of this, the SubjectDAO was created as the single point of control, and session state logic
                // has been moved to the DefaultSubjectDAO implementation.

                // Removed in Shiro 1.2.  SHIRO-157 is still satisfied by the new DefaultSubjectDAO implementation
                // introduced in 1.2
                // Satisfies SHIRO-157:
                // bindPrincipalsToSession(principals, context);

            } else {
                log.trace("No identity found.  Returning original context.");
            }

        }

        return context;
    }

    protected PrincipalCollection getRememberedIdentity(SubjectContext subjectContext) {

        RememberMeManager rmm = getRememberMeManager();
        if (rmm != null) {
            try {
                return rmm.getRememberedPrincipals(subjectContext);
            } catch (Exception e) {
                if (log.isWarnEnabled()) {
                    String msg = "Delegate RememberMeManager instance of type [" + rmm.getClass().getName() +
                            "] threw an exception during getRememberedPrincipals().";
                    log.warn(msg, e);
                }
            }
        }

        return null;
    }

    /**
     * Saves the subject's state to a persistent location for future reference if necessary.
     * <p/>
     * This implementation merely delegates to the internal {@link #setSubjectDAO(SubjectDAO) subjectDAO} and calls
     * {@link SubjectDAO#save(Subject) subjectDAO.save(subject)}.
     *
     * @param subject the subject for which state will potentially be persisted
     * @see SubjectDAO#save(Subject)
     */
    protected void save(WebSubject subject) {
        subjectDAO.save(subject);
        if (subject.isFromRememberedIdentity() && subject.isRemembered()) {
            // Ok, now the DAO has stored the Subject in the Session and thus HttpSession is created.
            // We now can sent an event (required for example for the ApplicationUsage) that there is a RememberedLogon.
            rememberMeLogonEvent.fire(new RememberMeLogonEvent(subject));
        }

    }

    /**
     * Actually creates a {@code Subject} instance by delegating to the internal
     * {@link #getSubjectFactory() subjectFactory}.  By the time this method is invoked, all possible
     * {@code SubjectContext} data (session, principals, et. al.) has been made accessible using all known heuristics
     * and will be accessible to the {@code subjectFactory} via the {@code subjectContext.resolve*} methods.
     *
     * @param context the populated context (data map) to be used by the {@code SubjectFactory} when creating a
     *                {@code Subject} instance.
     * @return a {@code Subject} instance reflecting the data in the specified {@code SubjectContext} data map.
     * @see #getSubjectFactory()
     * @see WebSubjectFactory#createSubject(SubjectContext)
     */
    protected WebSubject doCreateSubject(WebSubjectContext context) {

        return webSubjectFactory.createSubject(context);
    }

    public Session start(SessionContext context) throws AuthorizationException {
        return servletContainerSessionManager.createSession(context);
    }

    public WebSubject login(Subject webSubject, AuthenticationToken token) throws AuthenticationException {
        AuthenticationInfo info;
        try {
            info = authenticate(token);

        } catch (AuthenticationException ae) {
            try {
                onFailedLogin(token, ae, webSubject);
            } catch (Exception e) {
                if (log.isInfoEnabled()) {
                    log.info("onFailedLogin method threw an " +
                            "exception.  Logging and propagating original AuthenticationException.", e);
                }
            }
            throw ae; //propagate
        }

        WebSubject loggedIn;

        UserPrincipal userPrincipal = info.getPrincipals().getPrimaryPrincipal();

        boolean authenticated = true;
        if (twoStepManager.isTwoStepRequired() && !userPrincipal.isSystemAccount()) {  // FIXME Let the user decide if (s)he wants Two Step.
            authenticated = token instanceof OTPToken;
        }

        boolean rememberMe = false;
        if (token instanceof RememberMeAuthenticationToken) {
            rememberMe = ((RememberMeAuthenticationToken) token).isRememberMe();
        }

        loggedIn = createSubject(token, info, (WebSubject) webSubject, authenticated, rememberMe);

        if (loggedIn.isAuthenticated() || loggedIn.isRemembered()) {
            loggedIn.endTwoStepProcess();
            onSuccessfulLogin(token, info, loggedIn);
        } else {
            loggedIn.startTwoStepProcess();
            twoStepManager.startSecondStep(loggedIn);
        }

        return loggedIn;
    }

    /**
     * Delegates to the wrapped {@link Authenticator Authenticator} for authentication.
     */
    public AuthenticationInfo authenticate(AuthenticationToken token) throws AuthenticationException {
        return octopusRealm.authenticate(token);
    }

    protected void onSuccessfulLogin(AuthenticationToken token, AuthenticationInfo info, WebSubject subject) {
        // TODO Do we need to retrieve this on every login request or should we keep the handlers!
        List<AfterSuccessfulLoginHandler> handlers = CDIUtils.retrieveInstances(AfterSuccessfulLoginHandler.class);
        for (AfterSuccessfulLoginHandler handler : handlers) {
            handler.onSuccessfulLogin(token, info, subject);
        }

        rememberMeSuccessfulLogin(token, info, subject); // FIXME Convert the rememberMe to AfterSuccessfulLoginHandler?
        // But getRememberedIdentity need to stay here or we should make that also pluggable with some kind of handlers.

    }

    protected void onFailedLogin(AuthenticationToken token, AuthenticationException ae, Subject subject) {
        rememberMeFailedLogin(token, ae, subject); // Do the default stuff (with the rememberme manager

        if (token instanceof OTPToken) {
            // There is a failure in the validation of the OTP token
            // log the user out since authentication as a whole failed.
            subject.logout();
        }
    }

    protected void rememberMeSuccessfulLogin(AuthenticationToken token, AuthenticationInfo info, WebSubject subject) {

        RememberMeManager rmm = getRememberMeManager();
        if (rmm != null) {
            try {
                rmm.onSuccessfulLogin(subject, token, info);
            } catch (Exception e) {
                if (log.isWarnEnabled()) {
                    String msg = "Delegate RememberMeManager instance of type [" + rmm.getClass().getName() +
                            "] threw an exception during onSuccessfulLogin.  RememberMe services will not be " +
                            "performed for account [" + info + "].";
                    log.warn(msg, e);
                }
            }
        } else {
            if (log.isTraceEnabled()) {
                log.trace("This " + getClass().getName() + " instance does not have a " +
                        "[" + RememberMeManager.class.getName() + "] instance configured.  RememberMe services " +
                        "will not be performed for account [" + info + "].");
            }
        }

    }

    private RememberMeManager getRememberMeManager() {
        return rememberMeManagerProvider.getRememberMeManager();
    }

    protected void rememberMeFailedLogin(AuthenticationToken token, AuthenticationException ex, Subject subject) {

        RememberMeManager rmm = getRememberMeManager();
        if (rmm != null) {
            try {
                rmm.onFailedLogin(subject, token, ex);
            } catch (Exception e) {
                if (log.isWarnEnabled()) {
                    String msg = "Delegate RememberMeManager instance of type [" + rmm.getClass().getName() +
                            "] threw an exception during onFailedLogin for AuthenticationToken [" +
                            token + "].";
                    log.warn(msg, e);
                }
            }
        }

    }

    protected void rememberMeLogout(Subject subject) {

        RememberMeManager rmm = getRememberMeManager();
        if (rmm != null) {
            try {
                rmm.onLogout(subject);
            } catch (Exception e) {
                if (log.isWarnEnabled()) {
                    String msg = "Delegate RememberMeManager instance of type [" + rmm.getClass().getName() +
                            "] threw an exception during onLogout for subject with principals [" +
                            (subject != null ? subject.getPrincipals() : null) + "]";
                    log.warn(msg, e);
                }
            }
        }

    }

    protected void beforeLogout(Subject subject) {
        rememberMeLogout(subject);
        removeRequestIdentity(subject);
    }

    protected void removeRequestIdentity(Subject subject) {
        if (subject instanceof WebSubject) {
            WebSubject webSubject = (WebSubject) subject;
            ServletRequest request = webSubject.getServletRequest();
            if (request != null) {
                request.setAttribute(IDENTITY_REMOVED_KEY, Boolean.TRUE);
            }
        }
    }

    public void logout(Subject subject) {
        if (subject == null) {
            throw new AtbashIllegalActionException("(OCT-DEV-051) Subject method argument cannot be null.");
        }

        beforeLogout(subject);

        PrincipalCollection principals = subject.getPrincipals();
        // it is possible to have a Subject without PrincipalCollection?
        if (principals != null && !principals.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("Logging out subject with primary principal {}", principals.getPrimaryPrincipal());
            }
            octopusRealm.onLogout(principals);
        }

        try {
            delete((WebSubject) subject);
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                String msg = "Unable to cleanly unbind Subject.  Ignoring (logging out).";
                log.debug(msg, e);
            }
        } finally {
            try {
                stopSession((WebSubject) subject);
            } catch (Exception e) {
                if (log.isDebugEnabled()) {
                    String msg = "Unable to cleanly stop Session for Subject [" + subject.getPrincipal() + "] " +
                            "Ignoring (logging out).";
                    log.debug(msg, e);
                }
            }
        }


    }

    /**
     * Removes (or 'unbinds') the Subject's state from the application, typically called during {@link #logout}..
     * <p/>
     * This implementation merely delegates to the internal {@link #setSubjectDAO(SubjectDAO) subjectDAO} and calls
     * {@link SubjectDAO#delete(Subject) delete(subject)}.
     *
     * @param subject the subject for which state will be removed
     * @see SubjectDAO#delete(Subject)
     */
    protected void delete(WebSubject subject) {
        this.subjectDAO.delete(subject);
    }

    /**
     * Stop the session related to the Subject which results in the invalidation of the HTTP Session.
     * @param subject
     */
    protected void stopSession(WebSubject subject) {
        Session s = subject.getSession(false);
        if (s != null) {
            s.stop();
        }
    }
}
