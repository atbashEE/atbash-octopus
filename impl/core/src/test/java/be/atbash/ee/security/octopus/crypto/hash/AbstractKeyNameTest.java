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
package be.atbash.ee.security.octopus.crypto.hash;

import org.junit.jupiter.api.Disabled;

/**
 *
 */
@Disabled
public abstract class AbstractKeyNameTest {
    protected String defineExpectedName() {
        String expected;

        String version = Runtime.class.getPackage().getSpecificationVersion();
        if ("1.7".equals(version)) {
            expected = "PBKDF2WithHmacSHA1";
        } else {
            expected = "PBKDF2WithHmacSHA256";

        }
        return expected;
    }

}
