/*
 * Copyright 2014-2018 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.keycloak.adapter;

import be.atbash.config.exception.ConfigurationException;
import be.atbash.config.util.ResourceUtils;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;

import java.io.IOException;
import java.io.InputStream;

/**
 *
 */

public final class KeycloakDeploymentHelper {

    private KeycloakDeploymentHelper() {
    }

    public static KeycloakDeployment loadDeploymentDescriptor(String path) {

        InputStream inputStream = ResourceUtils.getInputStream(path);
        if (inputStream == null) {
            throw new ConfigurationException(String.format("unable to load keycloak deployment configuration from %s", path));
        }
        KeycloakDeployment result = KeycloakDeploymentBuilder.build(inputStream);

        try {
            inputStream.close();
        } catch (IOException e) {
            throw new AtbashUnexpectedException(e);

        }

        return result;
    }
}
