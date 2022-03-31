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
package be.atbash.ee.security.sso.server.endpoint;

import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.openid.connect.sdk.LogoutRequest;
import be.atbash.ee.security.octopus.SecurityUtils;
import be.atbash.ee.security.octopus.WebConstants;
import be.atbash.ee.security.octopus.config.Debug;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.nimbus.jwt.JWT;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.sso.server.client.ClientInfo;
import be.atbash.ee.security.sso.server.client.ClientInfoRetriever;
import be.atbash.ee.security.sso.server.store.OIDCStoreData;
import be.atbash.ee.security.sso.server.store.SSOTokenStore;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.inject.Inject;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Iterator;
import java.util.List;

/**
 *
 */

@WebServlet("/octopus/sso/logout")
public class LogoutServlet extends HttpServlet {

    private static final Logger LOGGER = LoggerFactory.getLogger(LogoutServlet.class);

    @Inject
    private OctopusCoreConfiguration octopusCoreConfiguration;

    @Inject
    private SSOTokenStore tokenStore;

    @Inject
    private ClientInfoRetriever clientInfoRetriever;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse resp) throws ServletException, IOException {
        LogoutRequest logoutRequest;
        try {
            logoutRequest = LogoutRequest.parse(request.getQueryString());
        } catch (OAuth2JSONParseException e) {
            // OWASP A6 : Sensitive Data Exposure
            throw new AtbashUnexpectedException(e);
            // TODO What should we return (check spec)
        }

        // We do not need to verify the JWT as this is already done by SSOLogoutFilter
        String clientId = getClientId(logoutRequest.getIDTokenHint());

        UserPrincipal userPrincipal = SecurityUtils.getSubject().getPrincipal();
        doSingleLogout(userPrincipal, clientId);
        tokenStore.removeUser(userPrincipal);

        if (logoutRequest.getPostLogoutRedirectionURI() != null) {
            // Only when we have logutRedirection (so no for Java SE case for example)
            try {
                resp.sendRedirect(logoutRequest.getPostLogoutRedirectionURI().toString());
            } catch (IOException e) {
                // OWASP A6 : Sensitive Data Exposure
                throw new AtbashUnexpectedException(e);
            }
        }

        SecurityUtils.getSubject().logout();

        showDebugInfo(userPrincipal);

    }

    private String getClientId(JWT idTokenHint) {
        return idTokenHint.getHeader().getCustomParameter("clientId").toString();
    }


    private void doSingleLogout(UserPrincipal userPrincipal, String clientId) {
        List<OIDCStoreData> loggedInClients = tokenStore.getLoggedInClients(userPrincipal);

        OIDCStoreData loggedInClient;
        Iterator<OIDCStoreData> iterator = loggedInClients.iterator();
        while (iterator.hasNext()) {
            loggedInClient = iterator.next();
            if (clientId.equals(loggedInClient.getClientId().getValue())) {
                iterator.remove();
            } else {

                ClientInfo clientInfo = clientInfoRetriever.retrieveInfo(loggedInClient.getClientId().getValue());
                if (clientInfo.isOctopusClient()) {
                    // TODO When it is not an Octopus client, we don't know the URL. forsee this in a future release
                    String url = clientInfo.getCallbackURL() + "/octopus/sso/SSOLogoutCallback?access_token=" + loggedInClient.getAccessToken().getValue();
                    sendLogoutRequestToClient(url);
                }
            }
        }
    }

    private void sendLogoutRequestToClient(String url) {
        try {
            URL obj = new URL(url);
            HttpURLConnection con = (HttpURLConnection) obj.openConnection();

            // optional default is GET
            con.setRequestMethod("GET");

            //add request header
            //con.setRequestProperty("User-Agent", USER_AGENT);

            int responseCode = con.getResponseCode();
            if (responseCode != 200) {
                LOGGER.warn(String.format("Sending logout request to %s failed with status :  %s, message : %s", url, responseCode, con.getResponseMessage()));
            }
        } catch (IOException e) {
            LOGGER.warn(String.format("Sending logout request to %s failed with %s", url, e.getMessage()));
        }
    }

    private void showDebugInfo(UserPrincipal user) {

        if (octopusCoreConfiguration.showDebugFor().contains(Debug.SSO_FLOW)) {
            LOGGER.info(String.format("(SSO Server) User %s is logged out (cookie token = %s)", user.getName(), user.getUserInfo(WebConstants.SSO_COOKIE_TOKEN)));
        }
    }
}