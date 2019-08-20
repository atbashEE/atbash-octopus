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
package be.atbash.ee.security.octopus.view;

import be.atbash.ee.security.octopus.SecurityUtils;
import be.atbash.ee.security.octopus.config.OctopusJSFConfiguration;
import be.atbash.ee.security.octopus.context.OctopusWebSecurityContext;
import be.atbash.ee.security.octopus.logout.LogoutHandler;
import be.atbash.ee.security.octopus.session.SessionUtil;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.util.SavedRequest;
import be.atbash.ee.security.octopus.util.WebUtils;
import be.atbash.util.Reviewed;
import be.atbash.util.exception.AtbashUnexpectedException;

import javax.enterprise.context.Dependent;
import javax.enterprise.inject.Specializes;
import javax.faces.context.ExternalContext;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 *
 */
@Specializes
@Dependent
public class OctopusJSFSecurityContext extends OctopusWebSecurityContext {

    @Inject
    private SessionUtil sessionUtil;

    @Inject
    private LogoutHandler logoutHandler;

    @Inject
    private OctopusJSFConfiguration octopusJSFConfiguration;

    public void loginWithRedirect(HttpServletRequest request, ExternalContext externalContext, AuthenticationToken token, String rootUrl) throws IOException {

        WebSubject subject = SecurityUtils.getSubject();

        boolean sessionInvalidate = true;
        if (subject.getPrincipal() != null && !subject.isAuthenticated()) {
            // This is the case for the TwoStep scenario when OTP value is requested.
            // In that case, we shouldn't invalidate the session since we already did it.
            sessionInvalidate = false;
        }
        if (sessionInvalidate) {
            sessionUtil.invalidateCurrentSession(request);
        }
        subject.login(token);

        if (SecurityUtils.getSubject().isAuthenticated()) {
            SavedRequest savedRequest = WebUtils.getAndClearSavedRequest(request);

            externalContext.redirect(savedRequest != null ? savedRequest.getRequestUrl() : rootUrl);
        } else {
            /*
            FIXME
            // Not authenticated, so we need to startup the Two Step authentication flow.
            TwoStepProvider twoStepProvider = BeanProvider.getContextualReference(TwoStepProvider.class);
            UserPrincipal principal = (UserPrincipal) SecurityUtils.getSubject().getPrincipal();
            twoStepProvider.startSecondStep(request, principal);

            */
            externalContext.redirect(request.getContextPath() + octopusJSFConfiguration.getSecondStepPage());
        }
    }

    @Reviewed
    public void logout() {

        // LogoutHandler requires access to the Principals. So only logout after the redirect.
        try {
            WebSubject subject = SecurityUtils.getSubject();
            WebUtils.issueRedirect(subject.getServletRequest(), subject.getServletResponse(), logoutHandler.getLogoutPage(), null, false, false);
        } catch (IOException e) {
            throw new AtbashUnexpectedException(e);
        }

        super.logout();
    }

}
