/*
 * Copyright 2014-2017 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.context;

import be.atbash.ee.security.octopus.SecurityUtils;
import be.atbash.ee.security.octopus.subject.Subject;

import javax.enterprise.context.Dependent;
import java.io.Serializable;

/**
 *
 */
@Dependent
public class OctopusSecurityContext implements Serializable {

    private Subject subject;

    public void prepareForAsyncUsage() {
        subject = SecurityUtils.getSubject();
    }

    public Subject getSubject() {
        Subject result = subject;
        if (subject != null) {

            subject = null;  // So that next calls make a anonymous user or the current Subject associated with the thread.
        } else {
            result = SecurityUtils.getSubject();
        }
        return result;
    }

    /*
    public void activateSystemAccount(String systemAccountIdentifier) {
        Subject subject = SecurityUtils.getSubject();
        if (subject.isAuthenticated()) {
            throw new SystemAccountActivationException();
        } else {
            // TODO Do we need to protect this by checking it is from a trusted place?
            SystemAccountPrincipal accountPrincipal = new SystemAccountPrincipal(systemAccountIdentifier);

            SecurityUtils.getSubject().login(new SystemAccountAuthenticationToken(accountPrincipal));
        }

    }
    */

    public static boolean isSystemAccount(Object principal) {
        return false;
        //return principal instanceof SystemAccountPrincipal; FIXME
    }

}