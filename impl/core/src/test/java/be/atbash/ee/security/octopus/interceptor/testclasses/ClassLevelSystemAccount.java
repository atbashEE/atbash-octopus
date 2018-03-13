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

import be.atbash.ee.security.octopus.interceptor.CallFeedbackCollector;
import be.atbash.ee.security.octopus.systemaccount.SystemAccount;

/**
 *
 */
@SystemAccount("account1")
public class ClassLevelSystemAccount {

    public static final String CLASS_LEVEL_SYSTEM_ACCOUNT = "ClassLevel#systemAccount";

    public void systemAccount1() {
        CallFeedbackCollector.addCallFeedback(CLASS_LEVEL_SYSTEM_ACCOUNT);
    }

    public void systemAccount2() {
        CallFeedbackCollector.addCallFeedback(CLASS_LEVEL_SYSTEM_ACCOUNT);
    }

}
