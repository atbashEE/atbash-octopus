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
package be.atbash.ee.security.octopus.provider;

import be.atbash.ee.security.octopus.SecurityUtils;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.ee.security.octopus.subject.UserPrincipal;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.context.RequestScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Named;

// FIXME Move to octopus-core? Can be used in Java SE CDI way of working
// Don't think it is a problem when using in classic JAVA SE (without CDI)

@ApplicationScoped  // Bean-mode : annotated
public class ProducerBean {

    @Produces
    @RequestScoped
    // FIXME This is not correctly proxied
    public Subject produceSubject() {
        return SecurityUtils.getSubject();
    }

    @Produces
    @RequestScoped
    @Named("userPrincipal")
    public UserPrincipal producePrincipal() {
        UserPrincipal result = null;
        Subject subject = SecurityUtils.getSubject();
        if (subject != null) {
            UserPrincipal principal = subject.getPrincipal();
            if (principal != null) {
                result = principal;
            }
        }
        if (result == null) {
            result = new UserPrincipal();
        }
        return result;
    }

    @Produces
    @Named("loggedInUser")
    public String produceUser() {
        String result = null;
        Subject subject = SecurityUtils.getSubject();
        if (subject != null) {
            UserPrincipal principal = subject.getPrincipal();
            if (principal != null) {
                result = principal.getName();
            }
        }
        return result;
    }
}
