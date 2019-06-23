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
package be.atbash.ee.security.octopus.cas.logout;

import be.atbash.ee.security.octopus.cas.config.OctopusCasConfiguration;
import be.atbash.ee.security.octopus.logout.LogoutParameters;
import be.atbash.ee.security.octopus.logout.LogoutURLProcessor;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

@ApplicationScoped
public class CasLogoutURLProcessor implements LogoutURLProcessor {

    @Inject
    private OctopusCasConfiguration octopusCasConfiguration;

    @Override
    public String postProcessLogoutUrl(String logoutURL, LogoutParameters parameters) {
        if (parameters.isSingleLogout()) {
            return octopusCasConfiguration.getSSOServer() + "/logout";
        } else {
            return logoutURL;
        }
    }
}
