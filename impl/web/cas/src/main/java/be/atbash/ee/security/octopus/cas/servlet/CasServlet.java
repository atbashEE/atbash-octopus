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
package be.atbash.ee.security.octopus.cas.servlet;

import be.atbash.ee.security.octopus.SecurityUtils;
import be.atbash.ee.security.octopus.authc.AuthenticationException;
import be.atbash.ee.security.octopus.cas.adapter.CasUserToken;
import be.atbash.ee.security.octopus.cas.adapter.info.CasInfoProvider;
import be.atbash.ee.security.octopus.config.OctopusJSFConfiguration;
import be.atbash.ee.security.octopus.session.SessionUtil;
import be.atbash.ee.security.octopus.session.usage.ActiveSessionRegistry;
import be.atbash.ee.security.octopus.util.SavedRequest;
import be.atbash.ee.security.octopus.util.WebUtils;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.jasig.cas.client.util.XmlUtils;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@WebServlet("/cas-callback")
public class CasServlet extends HttpServlet {

    // the name of the parameter service ticket in url
    private static final String TICKET_PARAMETER = "ticket";


    @Inject
    private CasInfoProvider casInfoProvider;

    @Inject
    private SessionUtil sessionUtil;

    @Inject
    private ActiveSessionRegistry activeSessionRegistry;

    @Inject
    private OctopusJSFConfiguration jsfConfiguration;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String ticket = request.getParameter(TICKET_PARAMETER);

        CasUserToken casUser = null;
        try {
            casUser = casInfoProvider.retrieveUserInfo(ticket);

            sessionUtil.invalidateCurrentSession(request);

            SecurityUtils.getSubject().login(casUser);

            //activeSessionRegistry.startSession(ticket, SecurityUtils.getSubject().getPrincipal());
            SavedRequest savedRequest = WebUtils.getAndClearSavedRequest(request);
            try {
                response.sendRedirect(savedRequest != null ? savedRequest.getRequestUrl() : request.getContextPath());
            } catch (IOException e) {
                // OWASP A6 : Sensitive Data Exposure
                throw new AtbashUnexpectedException(e);
            }

        } catch (AuthenticationException e) {
            HttpSession sess = request.getSession();
            sess.setAttribute(CasUserToken.CAS_USER_INFO, casUser);
            sess.setAttribute("AuthenticationExceptionMessage", e.getMessage());
            // DataSecurityProvider decided that google user has no access to application
            try {
                response.sendRedirect(request.getContextPath() + jsfConfiguration.getUnauthorizedExceptionPage());
            } catch (IOException ioException) {
                // OWASP A6 : Sensitive Data Exposure
                throw new AtbashUnexpectedException(ioException);
            }
        }
    }

    @Override
    protected void doPost(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {
        String logoutRequest = httpServletRequest.getParameter("logoutRequest");

        if (logoutRequest != null && logoutRequest.length() > 0) {
            if (logoutRequest.startsWith("<samlp:LogoutRequest")) {
                String sessionIdentifier = XmlUtils.getTextForElement(logoutRequest, "SessionIndex");
                //activeSessionRegistry.endSession(sessionIdentifier);
                // FIXME
            }
        }
        // TODO Do we need some logging when we receive post requests which doesn't contain the correct logout protocol?

    }
}
