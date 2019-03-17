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
package be.atbash.ee.security.octopus.otp;

import be.atbash.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.otp.config.OTPConfiguration;
import be.atbash.ee.security.octopus.otp.provider.DOTPProvider;
import be.atbash.ee.security.octopus.otp.provider.HOTPProvider;
import be.atbash.ee.security.octopus.otp.provider.SOTPProvider;
import be.atbash.ee.security.octopus.otp.provider.TOTPProvider;
import be.atbash.util.StringUtils;
import be.atbash.util.exception.AtbashUnexpectedException;
import be.atbash.util.resource.ResourceUtil;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 *
 */
@ApplicationScoped
public class OTPProviderFactory {

    @Inject
    private OTPConfiguration otpConfig;

    private OTPProvider otpProvider;

    public OTPProvider retrieveOTPProvider() {
        if (otpProvider == null) {
            otpProvider = createOTPProvider();
            Properties config = defineConfig();
            otpProvider.setProperties(otpConfig.getOTPLength(), config);
        }
        return otpProvider;
    }

    private Properties defineConfig() {
        Properties result;
        InputStream inputStream;
        String otpConfigFile = otpConfig.getOTPConfigFile();
        if (StringUtils.isEmpty(otpConfigFile)) {
            OctopusOTPAlgorithm algorithm = getOctopusOTPAlgorithm();
            if (algorithm != null) {
                switch (algorithm) {

                    case HOTP:
                        otpConfigFile = "classpath:/HOTPProvider.properties";
                        break;
                    case TOTP:
                        otpConfigFile = "classpath:/TOTPProvider.properties";
                        break;
                    case DOTP:
                        otpConfigFile = "classpath:/DOTPProvider.properties";
                        break;
                    case SOTP:
                        otpConfigFile = "classpath:/SOTPProvider.properties";
                        break;
                    default:
                        throw new IllegalArgumentException("Value supported " + algorithm);

                }
            }
        }
        ResourceUtil resourceUtil = ResourceUtil.getInstance();
        if (resourceUtil.resourceExists(otpConfigFile)) {
            try {
                inputStream = resourceUtil.getStream(otpConfigFile);
            } catch (IOException e) {
                throw new AtbashUnexpectedException(e);
            }
        } else {
            throw new ConfigurationException(String.format("OTP configuration file '%s' not found.", otpConfigFile));
        }

        result = new Properties();
        try {
            result.load(inputStream);
            inputStream.close();
        } catch (IOException e) {
            throw new AtbashUnexpectedException(e);
        }

        return result;
    }

    private OctopusOTPAlgorithm getOctopusOTPAlgorithm() {
        OctopusOTPAlgorithm algorithm = null;
        try {
            algorithm = OctopusOTPAlgorithm.valueOf(otpConfig.getOTPProvider());
        } catch (IllegalArgumentException e) {
            ;
            // We can't map it to an enum, so it should be the FQN of an OTPProvider
        }
        return algorithm;
    }

    private OTPProvider createOTPProvider() {
        OTPProvider result;

        OctopusOTPAlgorithm algorithm = getOctopusOTPAlgorithm();
        if (algorithm != null) {
            switch (algorithm) {

                case HOTP:
                    result = new HOTPProvider();
                    break;
                case TOTP:
                    result = new TOTPProvider();
                    break;
                case DOTP:
                    result = new DOTPProvider();
                    break;
                case SOTP:
                    result = new SOTPProvider();
                    break;
                default:
                    throw new IllegalArgumentException("Value supported " + algorithm);
            }
        } else {
            try {
                Class<?> aClass = Class.forName(otpConfig.getOTPProvider());
                result = (OTPProvider) aClass.newInstance();
            } catch (ClassNotFoundException e1) {
                throw new ConfigurationException("Class not found :" + otpConfig.getOTPProvider());
            } catch (InstantiationException e1) {
                throw new ConfigurationException("Instantiation Exception for " + otpConfig.getOTPProvider());
            } catch (IllegalAccessException e1) {
                throw new ConfigurationException("Illegal access Exception during instantiation of " + otpConfig.getOTPProvider());
            }
        }
        return result;
    }
}
