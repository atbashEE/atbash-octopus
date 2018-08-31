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
package be.atbash.ee.security.octopus.oauth2.google.servlet;

import be.atbash.ee.security.octopus.oauth2.google.GoogleProvider;
import be.atbash.ee.security.octopus.oauth2.info.OAuth2InfoProvider;
import be.atbash.ee.security.octopus.oauth2.servlet.OAuth2CallbackProcessor;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */
@ApplicationScoped
public class GoogleOAuth2CallbackProcessor extends OAuth2CallbackProcessor {

    @Inject
    @GoogleProvider
    private OAuth2InfoProvider infoProvider;

    @Override
    public void processCallback(HttpServletRequest request, HttpServletResponse response) throws IOException {

        //Check if the user is rejected
        String error = request.getParameter("error");
        if ((null != error) && ("access_denied".equals(error.trim()))) {
            logger.warn("Google informs us that no valid credentials are supplied or that consent is not given");
            redirectToRoot(request, response);
            return;
        }

        if (!checkCSRFToken(request, response)) {
            return;
        }

        //OK the user have consented so lets process authentication within Octopus
        doAuthenticate(request, response, infoProvider);

    }

}
