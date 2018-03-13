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
package be.atbash.ee.security.octopus.interceptor;

import be.atbash.ee.security.octopus.authz.permission.NamedDomainPermission;
import be.atbash.ee.security.octopus.authz.violation.SecurityViolationException;
import be.atbash.ee.security.octopus.interceptor.testclasses.ClassLevelOctopusPermissionWildCard;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import javax.interceptor.InvocationContext;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */
@RunWith(Parameterized.class)
public class OctopusInterceptor_ClassLevelOctopusPermissionWildCardTest extends OctopusInterceptorTest {

    public OctopusInterceptor_ClassLevelOctopusPermissionWildCardTest(boolean authenticated, String permission, boolean customAccess, String systemAccount, String role) {
        super(authenticated, permission, customAccess, systemAccount, role);
    }

    @Parameterized.Parameters
    public static List<Object[]> defineScenarios() {
        return Arrays.asList(new Object[][]{
                {NOT_AUTHENTICATED, null, NO_CUSTOM_ACCESS, null, null},            //0
                {NOT_AUTHENTICATED, null, CUSTOM_ACCESS, null, null},               //1
                {AUTHENTICATED, null, NO_CUSTOM_ACCESS, null, null},                //2
                {AUTHENTICATED, PERMISSION1_WILDCARD, NO_CUSTOM_ACCESS, null, null},        //3
                {AUTHENTICATED, PERMISSION2_WILDCARD, NO_CUSTOM_ACCESS, null, null},        //4
                {AUTHENTICATED, null, CUSTOM_ACCESS, null, null},                   //5
                {AUTHENTICATED, OCTOPUS1, NO_CUSTOM_ACCESS, null, null},            //6
                {AUTHENTICATED, null, NO_CUSTOM_ACCESS, ACCOUNT1, null},           //7
                {AUTHENTICATED, null, NO_CUSTOM_ACCESS, null, ROLE1},           //8
        });
    }

    @Test
    public void testInterceptShiroSecurity_octopusPermission1() throws Exception {

        Object target = new ClassLevelOctopusPermissionWildCard();
        Method method = target.getClass().getMethod("octopusPermission1");
        InvocationContext context = new TestInvocationContext(target, method);

        performAndCheck(context);
    }

    private void performAndCheck(InvocationContext context) throws Exception {

        finishCDISetup();

        securityCheckOctopusPermission.init();

        try {
            octopusInterceptor.interceptForSecurity(context);

            assertThat(permission).isEqualTo(PERMISSION1_WILDCARD);
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(ClassLevelOctopusPermissionWildCard.CLASS_LEVEL_OCTOPUS_PERMISSION);

        } catch (SecurityViolationException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();

            assertThat(permission).isNotEqualToIgnoringCase(PERMISSION1_WILDCARD);

        }
    }

    @Test
    public void testInterceptShiroSecurity_octopusPermission1Bis() throws Exception {

        Object target = new ClassLevelOctopusPermissionWildCard();
        Method method = target.getClass().getMethod("octopusPermission1Bis");
        InvocationContext context = new TestInvocationContext(target, method);

        performAndCheck(context);
    }

    protected NamedDomainPermission getNamedDomainPermission(String permissionName) {
        NamedDomainPermission result = null;
        if (permissionName != null) {

            result = new NamedDomainPermission(permissionName, permissionName);
        }
        return result;
    }

}

