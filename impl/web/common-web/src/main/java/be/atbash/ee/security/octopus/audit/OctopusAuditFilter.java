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
package be.atbash.ee.security.octopus.audit;

import be.atbash.ee.security.octopus.SecurityUtils;
import be.atbash.ee.security.octopus.filter.PathMatchingFilter;
import be.atbash.util.CDIUtils;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

/**
 *
 */
@ApplicationScoped
public class OctopusAuditFilter extends PathMatchingFilter {

    public static final String AUDIT_FILTER_NAME = "audit";

    @PostConstruct
    public void initInstance() {
        setName(AUDIT_FILTER_NAME);
    }

    @Override
    protected boolean onPreHandle(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest servletRequest = (HttpServletRequest) request;
        if (!"partial/ajax".equals(servletRequest.getHeader("Faces-Request"))) {
            Object principal = SecurityUtils.getSubject().getPrincipal();
            String requestURI = servletRequest.getRequestURI();
            int idx = requestURI.indexOf('/', 2);
            if (idx > 0) {
                requestURI = requestURI.substring(idx);
            }
            String remoteAddress = servletRequest.getRemoteAddr();

            String userAgent = ((HttpServletRequest)request).getHeader("User-Agent");
            CDIUtils.fireEvent(new OctopusAuditEvent(requestURI, principal, remoteAddress, userAgent));
        }

        return true;
    }
}
