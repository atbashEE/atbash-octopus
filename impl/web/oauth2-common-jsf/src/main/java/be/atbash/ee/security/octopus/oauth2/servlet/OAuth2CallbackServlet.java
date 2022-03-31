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
package be.atbash.ee.security.octopus.oauth2.servlet;

import be.atbash.ee.security.octopus.authz.UnauthenticatedException;
import be.atbash.ee.security.octopus.config.OctopusJSFConfiguration;
import be.atbash.ee.security.octopus.oauth2.metadata.OAuth2ProviderMetaDataControl;
import be.atbash.util.CDIUtils;
import be.atbash.util.exception.AtbashUnexpectedException;
import com.github.scribejava.core.exceptions.OAuthException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.inject.Inject;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */
@WebServlet(urlPatterns = {"/oauth2callback"})
public class OAuth2CallbackServlet extends HttpServlet {

    private Logger logger = LoggerFactory.getLogger(OAuth2CallbackServlet.class);

    @Inject
    private OAuth2ServletInfo oauth2ServletInfo;

    @Inject
    private OAuth2ProviderMetaDataControl oAuth2ProviderMetaDataControl;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {

            OAuth2CallbackProcessor processor;
            if (oauth2ServletInfo.getProviders().size() == 1) {
                processor = CDIUtils.retrieveInstance(OAuth2CallbackProcessor.class);

            } else {
                String userProviderSelection = oauth2ServletInfo.getSelection();
                Class<? extends OAuth2CallbackProcessor> callbackProcessor = oAuth2ProviderMetaDataControl.getProviderMetaData(userProviderSelection).getCallbackProcessor();
                processor = CDIUtils.retrieveInstance(callbackProcessor);
            }

            try {
                processor.processCallback(request, response);
            } catch (UnauthenticatedException exception) {
                // FIXME -> @Inject
                // FIXME Verify if this is thrown and correctly handled
                OctopusJSFConfiguration config = CDIUtils.retrieveInstance(OctopusJSFConfiguration.class);
                request.getRequestDispatcher(config.getUnauthorizedExceptionPage()).forward(request, response);
            } catch (OAuthException exception) {
                // FIXME Verify if this is thrown and correctly handled
                logger.warn(exception.getMessage());
                response.reset();
                response.setContentType("text/plain");
                response.getWriter().write("There was an issue processing the OAuth2 information.");
            }
        } catch (IOException e) {
            // OWASP A6 : Sensitive Data Exposure
            throw new AtbashUnexpectedException(e);
        }

    }

}