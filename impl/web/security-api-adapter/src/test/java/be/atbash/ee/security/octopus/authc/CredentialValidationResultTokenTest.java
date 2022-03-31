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
package be.atbash.ee.security.octopus.authc;

import org.junit.jupiter.api.Test;

import jakarta.security.enterprise.CallerPrincipal;
import jakarta.security.enterprise.identitystore.CredentialValidationResult;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

public class CredentialValidationResultTokenTest {

    @Test
    public void getPrincipal() {
        Set<String> groups = new HashSet<>();
        groups.add("group1");
        groups.add("group2");
        CredentialValidationResult validationResult = new CredentialValidationResult("JUnit Caller", groups);

        CredentialValidationResultToken token = new CredentialValidationResultToken(validationResult);
        Object principal = token.getPrincipal();

        assertThat(principal).isInstanceOf(CallerPrincipal.class);
        CallerPrincipal callerPrincipal = (CallerPrincipal) principal;
        assertThat(callerPrincipal.getName()).isEqualTo("JUnit Caller");
    }

    @Test
    public void getCredentials() {
        Set<String> groups = new HashSet<>();
        groups.add("group1");
        groups.add("group2");
        CredentialValidationResult validationResult = new CredentialValidationResult("JUnit Caller", groups);

        CredentialValidationResultToken token = new CredentialValidationResultToken(validationResult);
        Object credentials = token.getCredentials();

        assertThat(credentials).isNull();
    }

    @Test
    public void getCallerGroups() {
        Set<String> groups = new HashSet<>();
        groups.add("group1");
        groups.add("group2");
        CredentialValidationResult validationResult = new CredentialValidationResult("JUnit Caller", groups);

        CredentialValidationResultToken token = new CredentialValidationResultToken(validationResult);
        Set<String> callerGroups = token.getCallerGroups();
        assertThat(callerGroups).containsOnly("group1", "group2");
    }
}