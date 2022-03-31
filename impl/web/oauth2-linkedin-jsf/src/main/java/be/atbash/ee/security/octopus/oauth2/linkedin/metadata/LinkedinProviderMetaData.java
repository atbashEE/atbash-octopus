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
package be.atbash.ee.security.octopus.oauth2.linkedin.metadata;


import be.atbash.ee.security.octopus.oauth2.linkedin.servlet.LinkedinOAuth2CallbackProcessor;
import be.atbash.ee.security.octopus.oauth2.metadata.OAuth2ProviderMetaData;
import be.atbash.ee.security.octopus.oauth2.servlet.OAuth2CallbackProcessor;

import jakarta.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
public class LinkedinProviderMetaData implements OAuth2ProviderMetaData {

    //@Inject
    //@LinkedinProvider
    //private OAuth2InfoProvider infoProvider;

    @Override
    public String getServletPath() {
        return "/linkedin";
    }

    @Override
    public String getName() {
        return "Linkedin";
    }

    /*
    @Override
    public OAuth2InfoProvider getInfoProvider() {
        return infoProvider;
    }
    */

    @Override
    public Class<? extends OAuth2CallbackProcessor> getCallbackProcessor() {
        return LinkedinOAuth2CallbackProcessor.class;
    }

    /*
    @Override
    public Class<? extends AbstractOAuth2AuthcFilter> getOAuth2AuthcFilter() {
        return LinkedInAuthcFilter.class;
    }
    */
}
