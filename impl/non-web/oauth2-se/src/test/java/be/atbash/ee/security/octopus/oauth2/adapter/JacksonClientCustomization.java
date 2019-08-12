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
package be.atbash.ee.security.octopus.oauth2.adapter;

import be.atbash.ee.security.octopus.sso.client.ClientCustomization;
import org.glassfish.jersey.jackson.JacksonFeature;

import javax.ws.rs.client.Client;
import javax.ws.rs.core.Configuration;

public class JacksonClientCustomization implements ClientCustomization {
    // Required to register the JSON functionality when using Java SE.

    @Override
    public void customize(Client client, Class<?> clientUsageClass) {
        client.register(JacksonFeature.class);
    }

    @Override
    public Configuration getConfiguration(Class<?> clientUsageClass) {
        return null;
    }
}
