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
package be.atbash.ee.security.octopus.filter.authc;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.authc.AuthenticationException;
import be.atbash.ee.security.octopus.authz.UnauthenticatedException;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.UsernamePasswordToken;
import be.atbash.ee.security.octopus.util.ExceptionUtil;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.util.Arrays;

/**
 * An <code>AuthenticationFilter</code> that is capable of automatically performing an authentication attempt
 * based on the incoming request.
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.web.filter.authc.AuthenticatingFilter"})
public abstract class AuthenticatingFilter extends AuthenticationFilter {
    // To have the filter optionally work. like
    // authcBasic[PERMISSIVE] -> When basic info available use it otherwise it stays anonymous.
    public static final String PERMISSIVE = "permissive";

    //TODO - complete JavaDoc

    protected boolean executeLogin(ServletRequest request, ServletResponse response) throws Exception {
        AuthenticationToken token = createToken(request, response);
        if (token == null) {
            String msg = "createToken method implementation returned null. A valid non-null AuthenticationToken " +
                    "must be created in order to execute a login attempt.";
            throw new IllegalStateException(msg);
        }
        try {
            WebSubject subject = getSubject();
            subject.login(token);
            return onLoginSuccess(token, subject, request, response);
        } catch (AuthenticationException e) {
            return onLoginFailure(token, e, request, response);
        }
    }

    protected abstract AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception;

    protected AuthenticationToken createToken(String username, String password,
                                              ServletRequest request, ServletResponse response) {
        boolean rememberMe = isRememberMe(request);
        String host = getHost(request);
        return createToken(username, password, rememberMe, host);
    }

    protected AuthenticationToken createToken(String username, String password,
                                              boolean rememberMe, String host) {
        return new UsernamePasswordToken(username, password, rememberMe, host);
    }

    protected boolean onLoginSuccess(AuthenticationToken token, Subject subject,
                                     ServletRequest request, ServletResponse response) throws Exception {
        return true;
    }

    protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e,
                                     ServletRequest request, ServletResponse response) {
        return false;
    }

    /**
     * Returns the host name or IP associated with the current subject.  This method is primarily provided for use
     * during construction of an <code>AuthenticationToken</code>.
     * <p/>
     * The default implementation merely returns {@link ServletRequest#getRemoteHost()}.
     *
     * @param request the incoming ServletRequest
     * @return the <code>InetAddress</code> to associate with the login attempt.
     */
    protected String getHost(ServletRequest request) {
        return request.getRemoteHost();
    }

    /**
     * Returns <code>true</code> if &quot;rememberMe&quot; should be enabled for the login attempt associated with the
     * current <code>request</code>, <code>false</code> otherwise.
     * <p/>
     * This implementation always returns <code>false</code> and is provided as a template hook to subclasses that
     * support <code>rememberMe</code> logins and wish to determine <code>rememberMe</code> in a custom mannner
     * based on the current <code>request</code>.
     *
     * @param request the incoming ServletRequest
     * @return <code>true</code> if &quot;rememberMe&quot; should be enabled for the login attempt associated with the
     * current <code>request</code>, <code>false</code> otherwise.
     */
    protected boolean isRememberMe(ServletRequest request) {
        return false;
    }

    /**
     * Determines whether the current subject should be allowed to make the current request.
     * <p/>
     * The default implementation returns <code>true</code> if the user is authenticated.  Will also return
     * <code>true</code> if the {@link #isLoginRequest} returns false and the &quot;permissive&quot; flag is set.
     *
     * @return <code>true</code> if request should be allowed access
     */
    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        return super.isAccessAllowed(request, response, mappedValue) ||
                (!isLoginRequest(request) && isPermissive(mappedValue));
    }

    /**
     * Returns <code>true</code> if the mappedValue contains the {@link #PERMISSIVE} qualifier.
     *
     * @return <code>true</code> if this filter should be permissive
     */
    protected boolean isPermissive(Object mappedValue) {
        if (mappedValue != null) {
            String[] values = (String[]) mappedValue;
            return Arrays.binarySearch(values, PERMISSIVE) >= 0;
        }
        return false;
    }

    /**
     * Overrides the default behavior to call {@link #onAccessDenied} and swallow the exception if the exception is
     * {@link UnauthenticatedException}.
     */
    @Override
    protected void cleanup(ServletRequest request, ServletResponse response, Throwable existing) throws ServletException, IOException {
        Throwable unwrappedException = ExceptionUtil.unwrap(existing);
        if (ExceptionUtil.isUnauthenticatedException(unwrappedException)) {
            try {
                onAccessDenied(request, response);
                unwrappedException = null;
            } catch (Exception e) {
                unwrappedException = e;
            }
        }
        super.cleanup(request, response, unwrappedException);

    }
}
