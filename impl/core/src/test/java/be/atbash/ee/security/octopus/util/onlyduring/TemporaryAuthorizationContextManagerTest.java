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
package be.atbash.ee.security.octopus.util.onlyduring;

import org.junit.Test;

/**
 *
 */

public class TemporaryAuthorizationContextManagerTest {

    @Test(expected = WrongExecutionContextException.class)
    public void startInAuthorization_null() {
        TemporaryAuthorizationContextManager.startInAuthorization(null);
    }

    @Test(expected = WrongExecutionContextException.class)
    public void startInAuthorization_someClass() {
        TemporaryAuthorizationContextManager.startInAuthorization(String.class);
    }

    @Test(expected = WrongExecutionContextException.class)
    public void startInAuthorization_localMethodClass() {
        class Guard {
        }
        TemporaryAuthorizationContextManager.startInAuthorization(Guard.class);
    }

    @Test(expected = WrongExecutionContextException.class)
    public void startInAuthentication_null() {
        TemporaryAuthorizationContextManager.startInAuthentication(null);
    }

    @Test(expected = WrongExecutionContextException.class)
    public void startInAuthentication_someClass() {
        TemporaryAuthorizationContextManager.startInAuthentication(String.class);
    }

    @Test(expected = WrongExecutionContextException.class)
    public void startInAuthentication_localMethodClass() {
        class Guard {
        }
        TemporaryAuthorizationContextManager.startInAuthentication(Guard.class);
    }

    @Test(expected = WrongExecutionContextException.class)
    public void startInAuthenticationEvent_null() {
        TemporaryAuthorizationContextManager.startInAuthenticationEvent(null);
    }

    @Test(expected = WrongExecutionContextException.class)
    public void startInAuthenticationEvent_someClass() {
        TemporaryAuthorizationContextManager.startInAuthenticationEvent(String.class);
    }

    @Test(expected = WrongExecutionContextException.class)
    public void startInAuthenticationEvent_localMethodClass() {
        class Guard {
        }
        TemporaryAuthorizationContextManager.startInAuthenticationEvent(Guard.class);
    }

    @Test(expected = WrongExecutionContextException.class)
    public void startInSystemAccount_null() {
        TemporaryAuthorizationContextManager.startInSystemAccount(null);
    }

    @Test(expected = WrongExecutionContextException.class)
    public void startInSystemAccount_someClass() {
        TemporaryAuthorizationContextManager.startInSystemAccount(String.class);
    }

    @Test(expected = WrongExecutionContextException.class)
    public void startInSystemAccount_localMethodClass() {
        class Guard {
        }
        TemporaryAuthorizationContextManager.startInSystemAccount(Guard.class);
    }
}