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
package be.atbash.ee.security.octopus.filter.authc;


import be.atbash.ee.security.octopus.token.AuthenticationToken;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

/**
 *
 */
@ApplicationScoped
public class NoneFilter extends AuthenticatingFilter {

    @PostConstruct
    public void init() {
        setName("none");
    }

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        return false;
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        return false;
    }

    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response)  {
        // Needs to be implemented but of no concern here
        return null;
    }

    @Override
    protected void postHandle(ServletRequest request, ServletResponse response) throws Exception {
        response.reset();
        // TODO Is this casting always OK, should we change the parameter type?
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        httpServletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        httpServletResponse.setContentType("text/plain");
        httpServletResponse.getWriter().write("Access not allowed");
    }
}
