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
package be.atbash.ee.security.octopus.authz.violation;

import be.atbash.ee.security.octopus.authc.AuthenticationException;
import be.atbash.ee.security.octopus.authz.UnauthorizedException;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;

import javax.security.auth.login.AccountException;
import java.util.Set;

/**
 * TODO JavaDoc
 */

public class SecurityViolationException extends UnauthorizedException {

    private String message;
    private String exceptionPointInfo;

    public SecurityViolationException(String violation, String exceptionPointInfo) {
        message = violation;
        this.exceptionPointInfo = exceptionPointInfo;
    }

    public SecurityViolationException(Set<SecurityViolation> securityViolations) {
        StringBuilder violations = new StringBuilder();
        violations.append("Violation of ");
        boolean first = true;
        String violationName;
        String info;
        for (SecurityViolation violation : securityViolations) {
            if (!first) {
                violations.append(" - ");
            }
            // TODO Review this logic
            if (violation instanceof BasicAuthorizationViolation) {
                BasicAuthorizationViolation basicViolation = (BasicAuthorizationViolation) violation;
                violationName = basicViolation.getReason();
                info = basicViolation.getExceptionPoint();
            } else {
                if (violation.getReason().contains("@")) {
                    String[] parts = violation.getReason().split("@", 2);
                    violationName = parts[0];
                    info = parts[1];

                } else {
                    violationName = violation.getReason();
                    info = null;
                }
            }
            violations.append(violationName);
            if (exceptionPointInfo == null && info != null) {
                exceptionPointInfo = info;
            }
            first = false;
        }
        message = violations.toString();
    }

    public String getMessage() {
        return message;
    }

    public String getExceptionPointInfo() {
        return exceptionPointInfo;
    }

    public static Throwable getUnauthorizedException(Throwable someException) {
        // TODO Review reason?
        Throwable result = null;
        if (someException != null) {
            if (someException instanceof UnauthorizedException || someException instanceof AccountException || someException instanceof AuthenticationException) {
                result = someException;
            } else {
                if (someException.getCause() != null) {
                    result = getUnauthorizedException(someException.getCause());
                }
            }
        }
        return result;
    }
}
