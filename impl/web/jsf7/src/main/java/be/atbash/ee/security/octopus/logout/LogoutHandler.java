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
package be.atbash.ee.security.octopus.logout;

import be.atbash.ee.security.octopus.SecurityUtils;
import be.atbash.ee.security.octopus.config.OctopusJSFConfiguration;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.util.CDIUtils;
import be.atbash.util.Reviewed;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.util.List;

/**
 *
 */
@ApplicationScoped
@Reviewed
public class LogoutHandler {

    @Inject
    private OctopusJSFConfiguration octopusJSFConfiguration;

    private List<LogoutURLProcessor> logoutURLProcessors;

    @PostConstruct
    public void init() {
        logoutURLProcessors = CDIUtils.retrieveInstances(LogoutURLProcessor.class);
    }

    public String getLogoutPage() {
        String logoutUrl = octopusJSFConfiguration.getLogoutPage();

        Subject subject = SecurityUtils.getSubject();
        LogoutParameters parameters = new LogoutParameters(octopusJSFConfiguration.isSingleLogout(), subject.getPrincipals());

        for (LogoutURLProcessor processor : logoutURLProcessors) {
            logoutUrl = processor.postProcessLogoutUrl(logoutUrl, parameters);
        }
        return logoutUrl;
    }

}
