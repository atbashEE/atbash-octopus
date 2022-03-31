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
package be.atbash.ee.security.octopus.soteria.view;

import org.glassfish.soteria.identitystores.annotation.Credentials;
import org.glassfish.soteria.identitystores.annotation.EmbeddedIdentityStoreDefinition;

import jakarta.enterprise.inject.Model;

/**
 *
 */
@EmbeddedIdentityStoreDefinition({
        @Credentials(callerName = "rudy", password = "secret1", groups = {"foo", "bar", "role1"}),
        @Credentials(callerName = "will", password = "secret2", groups = {"kaz", "role2"}),
        @Credentials(callerName = "arjan", password = "secret3", groups = {"foo", "role1"})}
)

@Model
public class InfoBean {
    // We just needed a CDI bean where we could place the EmbeddedIdentityStoreDefinition
    // In real world application, it can be on any CDI bean.

}
