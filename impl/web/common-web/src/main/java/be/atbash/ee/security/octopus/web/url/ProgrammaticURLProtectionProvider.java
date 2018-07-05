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
package be.atbash.ee.security.octopus.web.url;

import java.util.LinkedHashMap;

/**
 * Allows to add URLs with filters pragmatically.
 * TODO Order is not defined, which could still give the opportunity to override 'internal' protection.
 * 'internal' are URLs defined by some modules (like OpenIdConnect server) which should not be changed
 */

public interface ProgrammaticURLProtectionProvider {

    LinkedHashMap<String, String> getURLEntriesToAdd();
    // FIXME For JSF add /javax.faces.resource/** anon -> so that all resources for page can be retrieved.
}
