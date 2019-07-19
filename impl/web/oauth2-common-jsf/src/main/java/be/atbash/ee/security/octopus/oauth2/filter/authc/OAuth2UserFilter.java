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
package be.atbash.ee.security.octopus.oauth2.filter.authc;

import be.atbash.ee.security.octopus.filter.authc.AbstractUserFilter;
import be.atbash.ee.security.octopus.oauth2.servlet.OAuth2ServletInfo;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

/**
 * Filter that allows access to resources if the accessor is a known user, which is defined as
 * having a known principal.  This means that any user who is authenticated or remembered via a
 * 'remember me' feature will be allowed access from this filter.
 * <p/>
 * If the accessor is not a known user, then they will be redirected to the OAuth2 login page of provider (or login.xhtml) when multiple providers</p>
 */
@ApplicationScoped
public class OAuth2UserFilter extends AbstractUserFilter {

    @Inject
    private OAuth2ServletInfo servletInfo;

    @PostConstruct
    public void initInstance() {
        setName("userOAuth2");

    }

    @Override
    public String getLoginUrl() {
        return servletInfo.getServletPath();
    }
}
