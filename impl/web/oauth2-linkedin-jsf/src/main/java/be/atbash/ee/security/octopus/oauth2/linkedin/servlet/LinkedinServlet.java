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
package be.atbash.ee.security.octopus.oauth2.linkedin.servlet;


import be.atbash.ee.security.octopus.oauth2.linkedin.provider.LinkedinOAuth2ServiceProducer;
import be.atbash.ee.security.octopus.oauth2.servlet.OAuth2Servlet;
import be.atbash.util.exception.AtbashUnexpectedException;

import jakarta.inject.Inject;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */
@WebServlet("/linkedin")
public class LinkedinServlet extends OAuth2Servlet {

    @Inject
    private LinkedinOAuth2ServiceProducer linkedinOAuth2ServiceProducer;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {

        try {
            redirectToAuthorizationURL(request, response, linkedinOAuth2ServiceProducer);
        } catch (IOException e) {
            // OWASP A6 : Sensitive Data Exposure
            throw new AtbashUnexpectedException(e);

        }
    }

}

