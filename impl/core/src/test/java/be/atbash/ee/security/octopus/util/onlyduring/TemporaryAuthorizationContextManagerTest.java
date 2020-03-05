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
package be.atbash.ee.security.octopus.util.onlyduring;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 *
 */

public class TemporaryAuthorizationContextManagerTest {

    @Test
    public void startInAuthorization_null() {
        Assertions.assertThrows(WrongExecutionContextException.class, () -> TemporaryAuthorizationContextManager.startInAuthorization(null));
    }

    @Test
    public void startInAuthorization_someClass() {
        Assertions.assertThrows(WrongExecutionContextException.class, () -> TemporaryAuthorizationContextManager.startInAuthorization(String.class));
    }

    @Test
    public void startInAuthorization_localMethodClass() {
        class Guard {
        }
        Assertions.assertThrows(WrongExecutionContextException.class, () -> TemporaryAuthorizationContextManager.startInAuthorization(Guard.class));
    }

    @Test
    public void startInAuthentication_null() {
        Assertions.assertThrows(WrongExecutionContextException.class, () -> TemporaryAuthorizationContextManager.startInAuthentication(null));
    }

    @Test
    public void startInAuthentication_someClass() {
        Assertions.assertThrows(WrongExecutionContextException.class, () -> TemporaryAuthorizationContextManager.startInAuthentication(String.class));
    }

    @Test
    public void startInAuthentication_localMethodClass() {
        class Guard {
        }
        Assertions.assertThrows(WrongExecutionContextException.class, () -> TemporaryAuthorizationContextManager.startInAuthentication(Guard.class));
    }

    @Test
    public void startInAuthenticationEvent_null() {
        Assertions.assertThrows(WrongExecutionContextException.class, () -> TemporaryAuthorizationContextManager.startInAuthenticationEvent(null));
    }

    @Test
    public void startInAuthenticationEvent_someClass() {
        Assertions.assertThrows(WrongExecutionContextException.class, () -> TemporaryAuthorizationContextManager.startInAuthenticationEvent(String.class));
    }

    @Test
    public void startInAuthenticationEvent_localMethodClass() {
        class Guard {
        }
        Assertions.assertThrows(WrongExecutionContextException.class, () -> TemporaryAuthorizationContextManager.startInAuthenticationEvent(Guard.class));
    }

    @Test
    public void startInSystemAccount_null() {
        Assertions.assertThrows(WrongExecutionContextException.class, () -> TemporaryAuthorizationContextManager.startInSystemAccount(null));
    }

    @Test
    public void startInSystemAccount_someClass() {
        Assertions.assertThrows(WrongExecutionContextException.class, () -> TemporaryAuthorizationContextManager.startInSystemAccount(String.class));
    }

    @Test
    public void startInSystemAccount_localMethodClass() {
        class Guard {
        }
        Assertions.assertThrows(WrongExecutionContextException.class, () -> TemporaryAuthorizationContextManager.startInSystemAccount(Guard.class));
    }
}