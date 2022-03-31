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
package be.atbash.ee.security.octopus.cas.filter.authc;

import be.atbash.ee.security.octopus.cas.config.OctopusCasConfiguration;
import be.atbash.ee.security.octopus.util.URLUtil;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.slf4j.Logger;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

/**
 *
 */
@ApplicationScoped
public class CasConfigurationHelper {

    @Inject
    private Logger logger;

    @Inject
    private OctopusCasConfiguration casConfiguration;

    @Inject
    private URLUtil urlUtil;

    private boolean loginUrlDefined = false;
    private String casService;
    private String loginUrl;

    public String defineCasLoginURL(HttpServletRequest request) {
        if (!loginUrlDefined) {
            defineLoginURL(request);
            loginUrlDefined = true;
            logger.info("CAS service = " + casService);
            casConfiguration.setCasService(casService);
        }
        return loginUrl;
    }

    private void defineLoginURL(HttpServletRequest request) {
        StringBuilder result = new StringBuilder();
        String ssoServer = casConfiguration.getSSOServer();
        result.append(ssoServer);
        if (!ssoServer.endsWith("/")) {
            result.append("/");
        }
        result.append("login?service=");

        casService = urlUtil.determineRoot(request) + "/cas-callback";

        try {
            result.append(URLEncoder.encode(casService, "UTF-8"));
        } catch (UnsupportedEncodingException e) {
            throw new AtbashUnexpectedException(e);
        }

        loginUrl = result.toString();
    }
}
