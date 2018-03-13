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
import be.atbash.ee.security.octopus.authz.permission.typesafe.PermissionLookupFixture;
import be.atbash.ee.security.octopus.authz.permission.voter.GenericPermissionVoter;
import be.atbash.ee.security.octopus.authz.violation.SecurityViolationException;
import be.atbash.ee.security.octopus.interceptor.testclasses.MultipleAtMethodLevel;
import be.atbash.ee.security.octopus.realm.OctopusRealm;
import be.atbash.util.TestReflectionUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import javax.interceptor.InvocationContext;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(Parameterized.class)
public class OctopusInterceptor_MultipleAtMethodLevelTest extends OctopusInterceptorTest {

    public OctopusInterceptor_MultipleAtMethodLevelTest(boolean authenticated, String permission, boolean customAccess, String systemAccount, String role) {
        super(authenticated, permission, customAccess, systemAccount, role);
    }

    @Parameterized.Parameters
    public static List<Object[]> defineScenarios() {
        return Arrays.asList(new Object[][]{
                {NOT_AUTHENTICATED, null, NO_CUSTOM_ACCESS, null, null},            //0
                {NOT_AUTHENTICATED, null, CUSTOM_ACCESS, null, null},               //1
                {AUTHENTICATED, null, NO_CUSTOM_ACCESS, null, null},                //2
                {AUTHENTICATED, PERMISSION1, NO_CUSTOM_ACCESS, null, null},        //3
                {AUTHENTICATED, null, CUSTOM_ACCESS, null, null},                   //4
                {AUTHENTICATED, OCTOPUS1, NO_CUSTOM_ACCESS, null, null},            //5
                {AUTHENTICATED, null, NO_CUSTOM_ACCESS, ACCOUNT1, null},           //6
                {AUTHENTICATED, null, NO_CUSTOM_ACCESS, null, ROLE1},            //7
        });
    }

    @Test
    public void testInterceptShiroSecurity_InAuthentication() throws Exception {

        // The in Authentication is so encapsulated that we can never set it outside the class (as we could manipulate then the security)
        // That is also the reason we have to simulate a larger part to test this.

        OctopusRealm octopusRealm = new OctopusRealm();

        when(octopusWebConfigurationMock.getHashAlgorithmName()).thenReturn("");


        /*
        TwoStepConfig twoStepConfigMock = Mockito.mock(TwoStepConfig.class);
        when(twoStepConfigMock.getAlwaysTwoStepAuthentication()).thenReturn(false);
        FIXME
        */

        TestReflectionUtils.injectDependencies(octopusRealm, authenticationInfoProviderHandlerMock, octopusWebConfigurationMock/*, twoStepConfigMock*/);
        registerPermissionVoter();

        Object target = new MultipleAtMethodLevel();
        Method method = target.getClass().getMethod("multiple");
        InvocationContext context = new TestInvocationContext(target, method);

        when(authenticationInfoProviderHandlerMock.retrieveAuthenticationInfo(null)).thenAnswer(
                callInterceptorSimulatingAuthentication(context)
        );

        finishCDISetup();

        try {
            octopusRealm.getAuthenticationInfo(null);

            if (PERMISSION1.equals(permission)) {
                assertThat(authenticated).isTrue();
            }
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MultipleAtMethodLevel.MULTIPLE_CHECKS);

        } catch (SecurityViolationException e) {
            assertThat(authenticated).isTrue();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @Test
    public void testInterceptShiroSecurity_CustomPermissionAnnotation() throws Exception {

        Object target = new MultipleAtMethodLevel();
        Method method = target.getClass().getMethod("multiple");
        InvocationContext context = new TestInvocationContext(target, method);

        registerPermissionVoter();

        PermissionLookupFixture.registerPermissionLookup(beanManagerFake);

        finishCDISetup();

        try {
            octopusInterceptor.interceptForSecurity(context);

            assertThat(permission).isEqualTo(PERMISSION1);
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MultipleAtMethodLevel.MULTIPLE_CHECKS);

        } catch (SecurityViolationException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();

        }
    }

    private void registerPermissionVoter() throws IllegalAccessException {
        GenericPermissionVoter permissionVoter = new GenericPermissionVoter();
        NamedDomainPermission namedPermission = getNamedDomainPermission(PERMISSION1);
        TestReflectionUtils.injectDependencies(permissionVoter, subjectMock, namedPermission);

        beanManagerFake.registerBean("permission1PermissionVoter", permissionVoter);
    }

}

