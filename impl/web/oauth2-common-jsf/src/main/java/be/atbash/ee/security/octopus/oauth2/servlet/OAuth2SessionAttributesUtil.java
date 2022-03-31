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

import com.github.scribejava.core.oauth.OAuth20Service;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

/**
 *
 */
@ApplicationScoped
public class OAuth2SessionAttributesUtil {

    private static final String OAUTH2_SERVICE = "octopus.oauth2Service";
    private static final String CSRF_TOKEN = "octopus.csrfToken";

    public void setOAuth2Service(HttpServletRequest request, OAuth20Service service) {
        HttpSession session = request.getSession();
        session.setAttribute(OAUTH2_SERVICE, service);
    }

    public void setCSRFToken(HttpServletRequest request, String token) {
        HttpSession session = request.getSession();
        session.setAttribute(CSRF_TOKEN, token);
    }

    public OAuth20Service getOAuth2Service(HttpServletRequest request) {
        HttpSession session = request.getSession();
        return (OAuth20Service) session.getAttribute(OAUTH2_SERVICE);
    }

    public String getCSRFToken(HttpServletRequest request) {
        HttpSession session = request.getSession();
        return (String) session.getAttribute(CSRF_TOKEN);
    }

}
