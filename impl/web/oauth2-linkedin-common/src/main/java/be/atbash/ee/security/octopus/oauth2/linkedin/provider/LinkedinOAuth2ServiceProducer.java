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
package be.atbash.ee.security.octopus.oauth2.linkedin.provider;

import be.atbash.ee.security.octopus.oauth2.config.OAuth2Configuration;
import be.atbash.ee.security.octopus.oauth2.provider.OAuth2ServiceProducer;
import be.atbash.util.StringUtils;
import com.github.scribejava.apis.LinkedInApi20;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.oauth.OAuth20Service;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.servlet.http.HttpServletRequest;

/**
 *
 */
@ApplicationScoped
public class LinkedinOAuth2ServiceProducer extends OAuth2ServiceProducer {

    @Inject
    private OAuth2Configuration configuration;

    /**
     * @param req
     * @param csrfToken value for the state parameter, allowed to be null in case you don't need it
     * @return
     */
    @Override
    public OAuth20Service createOAuthService(HttpServletRequest req, String csrfToken) {
        //Configure
        ServiceBuilder builder = new ServiceBuilder(configuration.getClientId());
        ServiceBuilder serviceBuilder = builder
                .apiSecret(configuration.getClientSecret())
                .callback(assembleCallbackUrl(req))
                .scope("r_basicprofile r_emailaddress " + configuration.getOAuth2Scopes())
                .debug();

        if (!StringUtils.isEmpty(csrfToken)) {
            serviceBuilder.state(csrfToken);
        }

        return serviceBuilder.build(LinkedInApi20.instance());
    }

}
