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
package be.atbash.ee.security.octopus.oauth2.google.servlet;


import be.atbash.util.exception.AtbashUnexpectedException;

import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */
@WebServlet("/usingMultipleAccounts")
public class MultipleAccountServlet extends HttpServlet {

    public static final String OCTOPUS_GOOGLE_MULTIPLE_ACCOUNTS = "OctopusGoogleMultipleAccounts";

    @Inject
    private Instance<MultipleAccountContent> multipleAccountContent;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        Boolean usingMultiple = Boolean.valueOf(request.getParameter("value"));
        setMultipleAccountCookie(response, !usingMultiple);
        // TODO When multiple MultipleAccountContent instances defined.
        if (!multipleAccountContent.isUnsatisfied()) {
            multipleAccountContent.get().doGet(request, response);
        } else {
            try {
                response.getWriter().write("Octopus : Multiple accounts for Google is active? " + usingMultiple);
            } catch (IOException e) {
                // OWASP A6 : Sensitive Data Exposure
                throw new AtbashUnexpectedException(e);

            }
        }
    }

    private void setMultipleAccountCookie(HttpServletResponse response, boolean remove) {
        Cookie cookie = new Cookie(OCTOPUS_GOOGLE_MULTIPLE_ACCOUNTS, "true");
        cookie.setComment("Triggers the account chooser from Google");
        if (remove) {
            cookie.setMaxAge(0);
        } else {

            cookie.setMaxAge(60 * 60 * 24 * 365 * 10); // 10 year
        }
        response.addCookie(cookie);
    }

}
