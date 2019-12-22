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
package be.atbash.ee.security.octopus.rememberme;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.config.RememberMeConfiguration;
import be.atbash.ee.security.octopus.realm.remember.AbstractRememberMeManager;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.ee.security.octopus.subject.SubjectContext;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.subject.support.WebSubjectContext;
import be.atbash.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.ServletRequest;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.util.Base64;

import static be.atbash.ee.security.octopus.WebConstants.IDENTITY_REMOVED_KEY;

/**
 * Remembers a Subject's identity by saving the Subject's {@link Subject#getPrincipals() principals} to a {@link Cookie}
 * for later retrieval.
 * <p/>
 * FIXME update javadoc for changed Cookie support (now only std and no longer custom written
 * Cookie attributes (name, maxAge, secure) may be set through the configuration, see RememberMeConfiguration.
 * created by this implementation.
 * <p/>
 * Note that because this class subclasses the {@link AbstractRememberMeManager} which already provides serialization
 * and encryption logic, this class utilizes both for added security before setting the cookie value.
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.web.mgt.CookieRememberMeManager"})
@ApplicationScoped
public class CookieRememberMeManager extends AbstractRememberMeManager {

    private static transient final Logger LOGGER = LoggerFactory.getLogger(CookieRememberMeManager.class);

    /**
     * Root path to use when the path hasn't been set and request context root is empty or null.
     */
    private static final String ROOT_PATH = "/";

    /**
     * The value of deleted cookie (with the maxAge 0).
     */
    private static final String DELETED_COOKIE_VALUE = "deleteMe";

    @Inject
    private RememberMeConfiguration rememberMeConfiguration;

    /**
     * Setup a default {@code rememberMe} cookie template.
     */
    @PostConstruct
    public void init() {
        setCipherKey(rememberMeConfiguration.getCipherKey());
    }

    /**
     * Returns the cookie 'template' that will be used to set all attributes of outgoing rememberMe cookies created by
     * this {@code RememberMeManager}.  Outgoing cookies will match this one except for the
     * {@link Cookie#getValue() value} attribute, which is necessarily set dynamically at runtime.
     * <p/>
     * Please see the class-level JavaDoc for the default cookie's attribute values.
     *
     * @return the cookie 'template' that will be used to set all attributes of outgoing rememberMe cookies created by
     * this {@code RememberMeManager}.
     */
    protected Cookie createCookie(String value, HttpServletRequest request) {
        Cookie cookie = new Cookie(getCookieName(), value);
        cookie.setHttpOnly(true);
        cookie.setMaxAge(rememberMeConfiguration.getCookieMaxAge());
        cookie.setSecure(rememberMeConfiguration.isCookieSecureOnly());
        cookie.setPath(calculatePath(request));

        return cookie;
    }

    /**
     * Returns the Cookie's calculated path setting.  It returns the
     * {@code request}'s {@link HttpServletRequest#getContextPath() context path}
     * will be returned. If getContextPath() is the empty string or null then the ROOT_PATH constant is returned.
     *
     * @param request the incoming HttpServletRequest
     * @return the path to be used as the path when the cookie is created or removed
     */
    protected String calculatePath(HttpServletRequest request) {

        String path = StringUtils.clean(request.getContextPath());

        //fix for http://issues.apache.org/jira/browse/SHIRO-9:
        if (path == null) {
            path = ROOT_PATH;
        }
        LOGGER.trace("calculated path: {}", path);
        return path;
    }

    /**
     * Base64-encodes the specified serialized byte array and sets that base64-encoded String as the cookie value.
     * <p/>
     * The {@code subject} instance is expected to be a {@link WebSubject} instance with an HTTP Request/Response pair
     * so an HTTP cookie can be set on the outgoing response.  If it is not a {@code WebSubject} or that
     * {@code WebSubject} does not have an HTTP Request/Response pair, this implementation does nothing.
     *
     * @param subject    the Subject for which the identity is being serialized.
     * @param serialized the serialized bytes to be persisted.
     */
    protected void rememberSerializedIdentity(Subject subject, byte[] serialized) {

        if (!(subject instanceof WebSubject)) {
            if (LOGGER.isDebugEnabled()) {
                String msg = "Subject argument is not an HTTP-aware instance.  This is required to obtain a servlet " +
                        "request and response in order to set the rememberMe cookie. Returning immediately and " +
                        "ignoring rememberMe operation.";
                LOGGER.debug(msg);
            }
            return;
        }

        WebSubject webSubject = (WebSubject) subject;

        HttpServletRequest request = webSubject.getServletRequest();
        HttpServletResponse response = webSubject.getServletResponse();

        //base 64 encode it and store as a cookie:
        String base64 = Base64.getEncoder().withoutPadding().encodeToString(serialized);

        Cookie cookie = createCookie(base64, request);
        response.addCookie(cookie);
    }

    private boolean isIdentityRemoved(WebSubjectContext subjectContext) {
        ServletRequest request = subjectContext.resolveServletRequest();
        if (request != null) {
            Boolean removed = (Boolean) request.getAttribute(IDENTITY_REMOVED_KEY);
            return removed != null && removed;
        }
        return false;
    }


    /**
     * Returns a previously serialized identity byte array or {@code null} if the byte array could not be acquired.
     * This implementation retrieves an HTTP cookie, Base64-decodes the cookie value, and returns the resulting byte
     * array.
     * <p/>
     * The {@code SubjectContext} instance is expected to be a {@link WebSubjectContext} instance with an HTTP
     * Request/Response pair so an HTTP cookie can be retrieved from the incoming request.  If it is not a
     * {@code WebSubjectContext} or that {@code WebSubjectContext} does not have an HTTP Request/Response pair, this
     * implementation returns {@code null}.
     *
     * @param subjectContext the contextual data that
     *                       is being used to construct a {@link Subject} instance.  To be used to assist with data
     *                       lookup.
     * @return a previously serialized identity byte array or {@code null} if the byte array could not be acquired.
     */
    protected byte[] getRememberedSerializedIdentity(SubjectContext subjectContext) {

        if (!(subjectContext instanceof WebSubjectContext)) {
            if (LOGGER.isDebugEnabled()) {
                String msg = "SubjectContext argument is not an HTTP-aware instance.  This is required to obtain a " +
                        "servlet request and response in order to retrieve the rememberMe cookie. Returning " +
                        "immediately and ignoring rememberMe operation.";
                LOGGER.debug(msg);
            }
            return null;
        }

        WebSubjectContext wsc = (WebSubjectContext) subjectContext;
        if (isIdentityRemoved(wsc)) {
            return null;
        }

        HttpServletRequest request = wsc.getServletRequest();

        String base64 = null;
        Cookie cookie = getCookie(request, getCookieName());
        if (cookie != null) {
            base64 = cookie.getValue();
        }
        // Browsers do not always remove cookies immediately (SHIRO-183)
        // ignore cookies that are scheduled for removal
        if (DELETED_COOKIE_VALUE.equals(base64)) {
            base64 = null;
        }

        if (base64 != null) {
            base64 = ensurePadding(base64);
            if (LOGGER.isTraceEnabled()) {
                LOGGER.trace(String.format("Acquired Base64 encoded identity [%s]", base64));
            }
            byte[] decoded = Base64.getDecoder().decode(base64);
            if (LOGGER.isTraceEnabled()) {
                LOGGER.trace(String.format("Base64 decoded byte array length: %s bytes.", decoded.length));
            }
            return decoded;
        } else {
            //no cookie set - new site visitor?
            return null;
        }
    }

    protected String getCookieName() {
        return rememberMeConfiguration.getCookieName();
    }

    /**
     * Returns the cookie with the given name from the request or {@code null} if no cookie
     * with that name could be found.
     *
     * @param request    the current executing http request.
     * @param cookieName the name of the cookie to find and return.
     * @return the cookie with the given name from the request or {@code null} if no cookie
     * with that name could be found.
     */
    private static Cookie getCookie(HttpServletRequest request, String cookieName) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(cookieName)) {
                    return cookie;
                }
            }
        }
        return null;
    }

    /**
     * Sometimes a user agent will send the rememberMe cookie value without padding,
     * most likely because {@code =} is a separator in the cookie header.
     * <p/>
     * Contributed by Luis Arias.  Thanks Luis!
     *
     * @param base64 the base64 encoded String that may need to be padded
     * @return the base64 String padded if necessary.
     */
    private String ensurePadding(String base64) {
        int length = base64.length();
        if (length % 4 != 0) {
            StringBuilder sb = new StringBuilder(base64);
            for (int i = 0; i < length % 4; ++i) {
                sb.append('=');
            }
            base64 = sb.toString();
        }
        return base64;
    }

    /**
     * Removes the 'rememberMe' cookie from the associated {@link WebSubject}'s request/response pair.
     * <p/>
     * The {@code subject} instance is expected to be a {@link WebSubject} instance with an HTTP Request/Response pair.
     * If it is not a {@code WebSubject} or that {@code WebSubject} does not have an HTTP Request/Response pair, this
     * implementation does nothing.
     *
     * @param subject the subject instance for which identity data should be forgotten from the underlying persistence
     */
    protected void forgetIdentity(Subject subject) {
        if ((subject instanceof WebSubject)) {
            WebSubject webSubject = (WebSubject) subject;
            forgetIdentity(webSubject.getServletRequest(), webSubject.getServletResponse());
        }
    }

    /**
     * Removes the 'rememberMe' cookie from the associated {@link WebSubjectContext}'s request/response pair.
     * <p/>
     * The {@code SubjectContext} instance is expected to be a {@link WebSubjectContext} instance with an HTTP
     * Request/Response pair.  If it is not a {@code WebSubjectContext} or that {@code WebSubjectContext} does not
     * have an HTTP Request/Response pair, this implementation does nothing.
     *
     * @param subjectContext the contextual data
     */
    public void forgetIdentity(SubjectContext subjectContext) {
        if ((subjectContext instanceof WebSubjectContext)) {
            WebSubjectContext webSubjectContext = (WebSubjectContext) subjectContext;
            forgetIdentity(webSubjectContext.getServletRequest(), webSubjectContext.getServletResponse());
        }
    }

    /**
     * Removes the rememberMe cookie from the given request/response pair.
     *
     * @param request  the incoming HTTP servlet request
     * @param response the outgoing HTTP servlet response
     */
    private void forgetIdentity(HttpServletRequest request, HttpServletResponse response) {
        Cookie cookie = createCookie(DELETED_COOKIE_VALUE, request);
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }
}

