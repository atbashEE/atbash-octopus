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
package be.atbash.ee.security.octopus.subject;

import be.atbash.ee.security.octopus.util.onlyduring.WrongExecutionContextException;
import org.junit.Test;

import java.io.Serializable;
import java.util.Map;

import static org.junit.Assert.*;

public class UserPrincipalTest {

    @Test
    public void addUserInfo() {
        UserPrincipal principal = new UserPrincipal();
        principal.addUserInfo("key", "value");
    }

    @Test(expected = WrongExecutionContextException.class)
    public void addUserInfo_wrong() {
        UserPrincipal principal = new UserPrincipal();
        principal.addUserInfo("octopus.key", "value");
    }

    @Test(expected = UnsupportedOperationException.class)
    // test immutable return of getInfo();
    public void getUserInfo() {
        UserPrincipal principal = new UserPrincipal();

        Map<String, Serializable> map = principal.getInfo();
        map.put("key", "value");
    }
}