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
package be.atbash.ee.security.octopus.authz;

import be.atbash.util.PublicAPI;
import be.atbash.util.Reviewed;

/**
 * When multiple permissions, roles and/or voters are specified. How are they combined. The default value is OR, one of the requirements are met, access is allowed.
 */
@PublicAPI
@Reviewed
public enum Combined {
    AND, OR;

    public static Combined findFor(String value) {
        Combined result = Combined.OR;

        if (value != null && "AND".equalsIgnoreCase(value.trim())) {
            result = Combined.AND;
        }

        return result;
    }
}
