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

import be.atbash.ee.security.octopus.authz.annotation.*;
import be.atbash.ee.security.octopus.authz.permission.testclasses.TestPermission;
import be.atbash.ee.security.octopus.interceptor.CallFeedbackCollector;
import be.atbash.ee.security.octopus.systemaccount.SystemAccount;

import javax.annotation.security.PermitAll;

/**
 *
 */
@PermitAll
public class MethodLevelOverride {

    public static final String METHOD_LEVEL_NO_ANNOTATION = "MethodLevelOverride#noAnnotation";
    public static final String METHOD_LEVEL_REQUIRES_USER = "MethodLevelOverride#requiresUser";
    public static final String METHOD_LEVEL_IN_AUTHENTICATION = "MethodLevelOverride#inAuthentication";
    public static final String METHOD_LEVEL_IN_AUTHORIZATION = "MethodLevelOverride#inAuthorization";
    public static final String METHOD_LEVEL_PERMISSION1 = "MethodLevelOverride#permission1";
    public static final String METHOD_LEVEL_PERMISSION2 = "MethodLevelOverride#permission2";
    public static final String METHOD_LEVEL_CUSTOM_VOTER = "MethodLevelOverride#customVoter";
    public static final String METHOD_LEVEL_REQUIRES_PERMISSION1 = "MethodLevelOverride#requiresPermission1";
    public static final String METHOD_LEVEL_REQUIRES_PERMISSION2 = "MethodLevelOverride#requiresPermission2";
    public static final String METHOD_LEVEL_SYSTEM_ACCOUNT1 = "MethodLevel#systemAccount1";
    public static final String METHOD_LEVEL_OCTOPUS_PERMISSION1 = "MethodLevel#octopusPermission1";
    public static final String METHOD_LEVEL_OCTOPUS_ROLE = "MethodLevel#octopusRole";

    public void noAnnotation() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_NO_ANNOTATION);
    }

    @RequiresUser
    public void requiresUser() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_REQUIRES_USER);
    }

    @OnlyDuringAuthentication
    public void inAuthentication() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_IN_AUTHENTICATION);
    }

    @OnlyDuringAuthorization
    public void inAuthorization() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_IN_AUTHORIZATION);
    }

    @TestPermissionCheck(TestPermission.PERMISSION1)
    public void permission1() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_PERMISSION1);
    }

    @TestPermissionCheck(TestPermission.PERMISSION2)
    public void permission2() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_PERMISSION2);
    }

    @CustomVoterCheck(TestCustomVoter.class)
    public void customVoter() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_CUSTOM_VOTER);
    }

    @RequiresPermissions("octopus1:*:*")
    public void requiresPermission1() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_REQUIRES_PERMISSION1);
    }

    @RequiresPermissions("octopus2:*:*")
    public void requiresPermission2() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_REQUIRES_PERMISSION2);
    }

    @SystemAccount("account1")
    public void systemAccountValue1() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_SYSTEM_ACCOUNT1);
    }

    @RequiresPermissions("permissionName")
    public void octopusPermission1() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_OCTOPUS_PERMISSION1);
    }

    @RequiresRoles("role1")
    public void octopusRole() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_OCTOPUS_ROLE);
    }

}
