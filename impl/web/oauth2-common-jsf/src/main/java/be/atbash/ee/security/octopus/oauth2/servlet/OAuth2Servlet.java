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
package be.atbash.ee.security.octopus.oauth2.servlet;

import be.atbash.ee.security.octopus.oauth2.csrf.CSRFTokenProducer;
import be.atbash.ee.security.octopus.oauth2.provider.OAuth2ServiceProducer;
import com.github.scribejava.core.oauth.OAuth20Service;

import javax.inject.Inject;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */
public abstract class OAuth2Servlet extends HttpServlet {

    @Inject
    private CSRFTokenProducer csrfTokenProducer;

    @Inject
    private OAuth2SessionAttributesUtil sessionAttributesUtil;

    protected void redirectToAuthorizationURL(HttpServletRequest request, HttpServletResponse response, OAuth2ServiceProducer serviceProducer) throws IOException {
        String token = csrfTokenProducer.nextToken();
        OAuth20Service service = serviceProducer.createOAuthService(request, token);

        sessionAttributesUtil.setOAuth2Service(request, service);
        sessionAttributesUtil.setCSRFToken(request, token);

        String authorizationUrl = service.getAuthorizationUrl();
        response.sendRedirect(postProcessAuthorizationUrl(request, authorizationUrl));
    }

    protected String postProcessAuthorizationUrl(HttpServletRequest request, String authorizationUrl) {
        return authorizationUrl;
    }

}
