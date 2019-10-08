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

import org.eclipse.microprofile.config.ConfigProvider;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

/**
 * Helper that redirects to an absolute, context relative, or current request
 * relative URL.
 * <p/>
 * A URL for this view is supposed to be a HTTP redirect URL, i.e.
 * suitable for HttpServletResponse's <code>sendRedirect</code> method, which
 * is what actually does the redirect if the HTTP 1.0 flag is on, or via sending
 * back an HTTP 303 code - if the HTTP 1.0 compatibility flag is off.
 * <p/>
 * The default value for the "contextRelative" flag is on, but you can set switch
 * off the parameter by setting HttpServletRequest.setAttribute(). With the flag off,
 * URLs starting with "/" are considered relative to the web server root, while
 * with the flag on, they are considered relative to the web application root.
 * Since most web apps will never know or care what their context path actually
 * is, they are much better off setting this flag to true, and submitting paths
 * which are to be considered relative to the web application root.
 * <p/>
 */
public final class RedirectHelper {

    private static RedirectHelper INSTANCE;

    private static final Object LOCK = new Object();

    private boolean http10Compatible;

    private RedirectHelper() {
        // TODO Do we need a 'configuration' for this so that it gets printed at startup?
        Optional<String> compatible = ConfigProvider.getConfig().getOptionalValue("redirect.http10.compatible", String.class);
        http10Compatible = compatible.map(Boolean::parseBoolean).orElse(true);
    }

    private String prepareURL(HttpServletRequest servletRequest, String url) {
        // Prepare name URL.
        StringBuilder targetUrl = new StringBuilder();
        if (isContextRelative(servletRequest) && url.startsWith("/")) {
            // Do not apply context path to relative URLs.
            targetUrl.append(servletRequest.getContextPath());
        }
        targetUrl.append(url);

        return targetUrl.toString();
    }

    private boolean isContextRelative(HttpServletRequest servletRequest) {
        boolean result = true;
        Object attribute = servletRequest.getAttribute(WebConstants.REDIRECT_CONTEXT_RELATIVE);
        if (attribute != null) {
            result = (boolean) attribute;
        }
        return result;
    }

    /**
     * Send a redirect back to the HTTP client
     *
     * @param request  current HTTP request (allows for reacting to request method)
     * @param response current HTTP response (for sending response headers)
     * @param url      the name URL to redirect to
     * @throws IOException if thrown by response methods
     */
    @SuppressWarnings({"UnusedDeclaration"})
    public void sendRedirect(HttpServletRequest request, HttpServletResponse response,
                             String url) throws IOException {
        String targetUrl = prepareURL(request, url);

        if (isHttp10Compatible(request)) {
            // Always send status code 302.
            response.sendRedirect(response.encodeRedirectURL(targetUrl));
        } else {
            // Correct HTTP status code is 303, in particular for POST requests.
            response.setStatus(303);
            response.setHeader("Location", response.encodeRedirectURL(targetUrl));
        }
    }

    private boolean isHttp10Compatible(HttpServletRequest servletRequest) {
        boolean result = http10Compatible;
        Object attribute = servletRequest.getAttribute(WebConstants.REDIRECT_HTTP10_COMPATIBLE);
        if (attribute != null) {
            result = (boolean) attribute;
        }
        return result;

    }

    public static RedirectHelper getInstance() {
        if (INSTANCE == null) {
            synchronized (LOCK) {
                if (INSTANCE == null) {
                    INSTANCE = new RedirectHelper();
                }
            }
        }
        return INSTANCE;
    }
}
