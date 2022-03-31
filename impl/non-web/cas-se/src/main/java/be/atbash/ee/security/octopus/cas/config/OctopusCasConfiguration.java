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
package be.atbash.ee.security.octopus.cas.config;

import be.atbash.config.AbstractConfiguration;
import be.atbash.config.logging.ConfigEntry;
import be.atbash.config.logging.ModuleConfig;
import be.atbash.config.logging.ModuleConfigName;
import be.atbash.config.logging.StartupLogging;
import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import be.atbash.util.StringUtils;
import be.atbash.util.exception.AtbashUnexpectedException;
import be.atbash.util.CDICheck;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.enterprise.context.ApplicationScoped;
import javax.net.ssl.*;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 *
 */
@ApplicationScoped
@ModuleConfigName("Octopus CAS Configuration")
public class OctopusCasConfiguration extends AbstractConfiguration implements ModuleConfig {

    private static final Logger LOGGER = LoggerFactory.getLogger(OctopusCasConfiguration.class);

    private String casService;

    @ConfigEntry
    public String getCASEmailProperty() {
        return getOptionalValue("CAS.property.email", "email", String.class);
    }

    @ConfigEntry
    public String getSSOServer() {
        // FIXME Also support SSO.server. Make same as KeyCloak (verify)
        String result = getOptionalValue("CAS.SSO.server", String.class);
        if (StringUtils.isEmpty(result)) {
            throw new ConfigurationException("A value for 'CAS.SSO.server' is required.");
        }
        return result;
    }

    @ConfigEntry
    public CASProtocol getCASProtocol() {

        String casProtocol = getOptionalValue("CAS.protocol", "CAS", String.class);

        // SAML should also be supported, but not tested for the moment.

        CASProtocol result = CASProtocol.fromValue(casProtocol);
        if (result == null) {
            throw new ConfigurationException(String.format("Invalid value for parameter CAS.protocol specified : %s (CAS or SAML allowed)", casProtocol));
        }
        return result;
    }

    @ConfigEntry
    public String getCASService() {
        if (casService == null) {
            casService = getOptionalValue("CAS.service", String.class);
        }
        return casService;
    }

    public void setCasService(String casService) {
        this.casService = casService;
    }

    @ConfigEntry
    public boolean isSSLCheckDisabled() {
        // This method will never be called by code. But due to the Logging of config at startup, it gets executed
        // and as a side effect, the SSL Context gets adapted
        Boolean sslDisabled = getOptionalValue("CAS.SSL.disabled", Boolean.FALSE, Boolean.class);
        if (sslDisabled) {
            disableSSLChecks();
        }
        return sslDisabled;
    }

    private void disableSSLChecks() {
        try {
            HostnameVerifier allHostsValid = (hostname, session) -> true;
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);

            SSLContext ctx = SSLContext.getInstance("SSL");
            ctx.init(new KeyManager[0], new TrustManager[]{new NOOPTrustManager()}, new SecureRandom());
            SSLContext.setDefault(ctx);

            LOGGER.warn("The SSL checks are disabled for CAS access.This means no DNS and Certificate checks are performed when accessing CAS endpoints. This is a huge risk and only acceptable for DEV environment");
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new AtbashUnexpectedException(e);
        }

    }

    // Java SE Support
    private static OctopusCasConfiguration INSTANCE;

    private static final Object LOCK = new Object();

    public static OctopusCasConfiguration getInstance() {
        if (INSTANCE == null) {
            synchronized (LOCK) {
                if (INSTANCE == null) {
                    INSTANCE = new OctopusCasConfiguration();
                    if (!CDICheck.withinContainer()) {
                        StartupLogging.logConfiguration(INSTANCE);
                    }
                }
            }
        }
        return INSTANCE;
    }

}
