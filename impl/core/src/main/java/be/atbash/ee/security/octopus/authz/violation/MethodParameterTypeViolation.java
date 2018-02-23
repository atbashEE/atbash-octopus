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

import be.atbash.util.PublicAPI;

import java.util.List;

/**
 * TODO JavaDoc
 */
@PublicAPI
public class MethodParameterTypeViolation extends BasicAuthorizationViolation {

    private String reason;

    public MethodParameterTypeViolation(String exceptionPoint, List<Class<?>> missingParameterTypes) {
        super(null, exceptionPoint);
        this.reason = getInfoAboutMissingParameterTypes(missingParameterTypes);
    }

    @Override
    public String getReason() {
        return reason;
    }

    private String getInfoAboutMissingParameterTypes(List<Class<?>> missingParameterTypes) {
        StringBuilder result = new StringBuilder();
        result.append("Method needs to have parameter(s) of following type :");
        boolean first = true;
        for (Class<?> type : missingParameterTypes) {
            if (!first) {
                result.append(", ");
            }
            result.append(type.getName());
            first = false;
        }
        return result.toString();
    }
}
