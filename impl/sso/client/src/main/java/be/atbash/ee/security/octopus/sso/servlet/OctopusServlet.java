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
package be.atbash.ee.security.octopus.sso.servlet;

import be.atbash.ee.security.octopus.sso.ClientCallbackHelper;
import be.atbash.ee.security.octopus.sso.client.OpenIdVariableClientData;
import be.atbash.ee.security.octopus.sso.config.OctopusSSOClientConfiguration;
import be.atbash.ee.security.octopus.sso.core.SSOConstants;
import be.atbash.ee.security.octopus.util.URLUtil;
import be.atbash.util.CDIUtils;
import be.atbash.util.exception.AtbashUnexpectedException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.slf4j.Logger;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

/**
 *
 */
@WebServlet("/octopus")
public class OctopusServlet extends HttpServlet {

    @Inject
    private Logger logger;

    @Inject
    private URLUtil urlUtil;

    @Inject
    private OctopusSSOClientConfiguration octopusSSOClientConfiguration;

    private ClientCallbackHelper clientCallbackHelper;

    @Override
    public void init() throws ServletException {
        clientCallbackHelper = CDIUtils.retrieveOptionalInstance(ClientCallbackHelper.class);
    }

    @Override
    protected void doGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {

        String rootURL;
        if (clientCallbackHelper == null) {
            rootURL = urlUtil.determineRoot(httpServletRequest);
        } else {
            rootURL = clientCallbackHelper.determineCallbackRoot(httpServletRequest);
        }

        OpenIdVariableClientData variableClientData = new OpenIdVariableClientData(rootURL);
        storeClientData(httpServletRequest, variableClientData);

        String actualLoginURL = determineActualLoginURL(variableClientData);
        try {
            httpServletResponse.sendRedirect(actualLoginURL);
        } catch (IOException e) {
            // OWASP A6 : Sensitive Data Exposure
            throw new AtbashUnexpectedException(e);

        }

    }

    private String determineActualLoginURL(OpenIdVariableClientData variableClientData) {

        String partialLoginURL = octopusSSOClientConfiguration.getLoginPage();

        AuthenticationRequest req;
        try {
            URI callback = new URI(variableClientData.getRootURL() + SSOConstants.SSO_CALLBACK_PATH);
            ClientID clientId = new ClientID(octopusSSOClientConfiguration.getSSOClientId());
            req = new AuthenticationRequest(
                    new URI(partialLoginURL),
                    octopusSSOClientConfiguration.getSSOType().getResponseType(),
                    Scope.parse("openid octopus " + octopusSSOClientConfiguration.getSSOScopes()),
                    clientId,
                    callback,
                    variableClientData.getState(),
                    variableClientData.getNonce());
        } catch (URISyntaxException e) {
            throw new AtbashUnexpectedException(e);
        }

        return partialLoginURL + '?' + req.toHTTPRequest().getQuery();

    }

    private void storeClientData(HttpServletRequest request, OpenIdVariableClientData variableClientData) {
        HttpSession session = request.getSession(true);

        if (session.getAttribute(OpenIdVariableClientData.class.getName()) != null) {
            logger.warn("State and Nonce value for OpenIdConnect already present within session");
        }
        // TODO The idea was that within a session, there could be only 1 logon attempt.
        // But there where some issue reported in more complex situations so this check is disabled for the moment.
        // The above warning is added as compensation so that there is a trace how many times it happen.
        //if (session.getAttribute(OpenIdVariableClientData.class.getName()) == null) {

        session.setAttribute(OpenIdVariableClientData.class.getName(), variableClientData);
        //}
    }


}
