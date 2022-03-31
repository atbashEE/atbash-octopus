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
package be.atbash.ee.security.octopus.authz;

import be.atbash.ee.security.octopus.filter.authz.AccessDeniedHandler;
import be.atbash.ee.security.octopus.filter.mgt.ErrorInfo;
import be.atbash.ee.security.octopus.util.WebUtils;
import be.atbash.util.Reviewed;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

import static be.atbash.ee.security.octopus.OctopusConstants.OCTOPUS_VIOLATION_MESSAGE;

/**
 *
 */
@Reviewed
@ApplicationScoped
public class RestAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public boolean onAccessDenied(ServletRequest request, ServletResponse response) throws IOException {
        String message = "Unable to determine the message";

        Object attribute = request.getAttribute(OCTOPUS_VIOLATION_MESSAGE);
        if (attribute != null) {
            message = attribute.toString();
        }
        ErrorInfo info = new ErrorInfo("OCT-002", message);

        HttpServletResponse servletResponse = WebUtils.toHttp(response);

        servletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        servletResponse.setHeader("Content-Type", "application/json");
        servletResponse.getWriter().print(info.toJSON());

        return false;
    }
}
