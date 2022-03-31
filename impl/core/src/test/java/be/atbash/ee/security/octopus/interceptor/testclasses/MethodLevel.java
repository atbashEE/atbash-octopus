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
package be.atbash.ee.security.octopus.interceptor.testclasses;

import be.atbash.ee.security.octopus.authz.Combined;
import be.atbash.ee.security.octopus.authz.annotation.*;
import be.atbash.ee.security.octopus.authz.permission.testclasses.TestPermission;
import be.atbash.ee.security.octopus.interceptor.CallFeedbackCollector;
import be.atbash.ee.security.octopus.systemaccount.SystemAccount;

import jakarta.annotation.security.PermitAll;

/**
 *
 */
public class MethodLevel {

    public static final String METHOD_LEVEL_PERMIT_ALL = "MethodLevel#permitAll";
    public static final String METHOD_LEVEL_REQUIRES_USER = "MethodLevel#requiresUser";
    public static final String METHOD_LEVEL_IN_AUTHENTICATION = "MethodLevel#inAuthentication";
    public static final String METHOD_LEVEL_IN_AUTHORIZATION = "MethodLevel#inAuthorization";
    public static final String METHOD_LEVEL_PERMISSION1 = "MethodLevel#permission1";
    public static final String METHOD_LEVEL_PERMISSION2 = "MethodLevel#permission2";
    public static final String METHOD_LEVEL_CUSTOM_VOTER = "MethodLevel#customVoter";
    public static final String METHOD_LEVEL_REQUIRES_PERMISSION1 = "MethodLevel#requiresPermission1";
    public static final String METHOD_LEVEL_REQUIRES_PERMISSION2 = "MethodLevel#requiresPermission2";
    public static final String METHOD_LEVEL_SYSTEM_ACCOUNT1 = "MethodLevel#systemAccount1";
    public static final String METHOD_LEVEL_SYSTEM_ACCOUNT2 = "MethodLevel#systemAccount2";
    public static final String METHOD_LEVEL_OCTOPUS_PERMISSION1 = "MethodLevel#octopusPermission1";
    public static final String METHOD_LEVEL_OCTOPUS_PERMISSION3 = "MethodLevel#octopusPermission3";
    public static final String METHOD_LEVEL_OCTOPUS_PERMISSION4 = "MethodLevel#octopusPermission4";
    public static final String METHOD_LEVEL_OCTOPUS_ROLE = "MethodLevel#octopusRole";
    public static final String METHOD_LEVEL_CUSTOM_CHECK_BASIC = "MethodLevel#customCheck_Basic";
    public static final String METHOD_LEVEL_CUSTOM_CHECK_EXTENDED = "MethodLevel#customCheck_Extended";

    @PermitAll
    public void permitAll() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_PERMIT_ALL);
    }

    public void noAnnotation() {
        CallFeedbackCollector.addCallFeedback("MethodLevel#noAnnotation");
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

    @SystemAccount("account2")
    public void systemAccountValue2() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_SYSTEM_ACCOUNT2);
    }

    @RequiresPermissions("permissionName")
    public void octopusPermission1() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_OCTOPUS_PERMISSION1);
    }

    @RequiresPermissions({"octopus:action:*", "permissionName"})
    public void octopusPermission3() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_OCTOPUS_PERMISSION3);
    }

    @RequiresPermissions(value = {"octopus:action:*", "permissionName"}, combined = Combined.AND)
    public void octopusPermission4() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_OCTOPUS_PERMISSION4);
    }

    @RequiresRoles("role1")
    public void octopusRole() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_OCTOPUS_ROLE);
    }

    @AdditionalAnnotation
    @Deprecated  // This should not be picked up, testing for the AnnotationUtil.getAllAnnotations
    public void additionalAnnotation() {
    }

    @MyCheck(value = "Permission1", info = MyCheckInfo.BASIC)
    public void customBasic() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_CUSTOM_CHECK_BASIC);
    }

    @MyCheck(value = "Permission1", info = MyCheckInfo.EXTENDED)
    public void customExtended() {
        CallFeedbackCollector.addCallFeedback(METHOD_LEVEL_CUSTOM_CHECK_EXTENDED);
    }

    @MyCheck(value = "value1Bis", info = MyCheckInfo.BASIC)
    public void getStringValue1Bis() {
    }

    @RequiresPermissions({"value2", "value3"})
    public void getStringValue2() {

    }

    @MyAdvancedCheck()
    public void getDataWithAdvancedChecks() {
    }

}

