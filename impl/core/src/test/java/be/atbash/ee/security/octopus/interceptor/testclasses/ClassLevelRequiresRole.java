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
package be.atbash.ee.security.octopus.interceptor.testclasses;

import be.atbash.ee.security.octopus.authz.annotation.RequiresRoles;
import be.atbash.ee.security.octopus.interceptor.CallFeedbackCollector;

/**
 *
 */
@RequiresRoles("role1")
public class ClassLevelRequiresRole {

    public static final String CLASS_LEVEL_OCTOPUS_ROLE = "ClassLevel#octopusRole";

    public void octopusRole1() {
        CallFeedbackCollector.addCallFeedback(CLASS_LEVEL_OCTOPUS_ROLE);
    }

    public void octopusRole1Bis() {
        CallFeedbackCollector.addCallFeedback(CLASS_LEVEL_OCTOPUS_ROLE);
    }

}
