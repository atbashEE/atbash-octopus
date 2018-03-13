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

import be.atbash.ee.security.octopus.authz.UnauthorizedException;
import be.atbash.ee.security.octopus.authz.permission.NamedDomainPermission;
import be.atbash.ee.security.octopus.authz.permission.StringPermissionLookup;
import be.atbash.ee.security.octopus.authz.permission.typesafe.PermissionLookupFixture;
import be.atbash.ee.security.octopus.authz.permission.voter.GenericPermissionVoter;
import be.atbash.ee.security.octopus.authz.violation.SecurityViolationException;
import be.atbash.ee.security.octopus.interceptor.testclasses.MethodLevel;
import be.atbash.ee.security.octopus.realm.OctopusRealm;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.subject.SimplePrincipalCollection;
import be.atbash.util.TestReflectionUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.ArgumentMatchers;

import javax.interceptor.InvocationContext;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(Parameterized.class)
public class OctopusInterceptor_MethodLevelTest extends OctopusInterceptorTest {

    public OctopusInterceptor_MethodLevelTest(boolean authenticated, String permission, boolean customAccess, String systemAccount, String role) {
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
                {AUTHENTICATED, NAMED_OCTOPUS, NO_CUSTOM_ACCESS, null, null},        //7
                {AUTHENTICATED, null, NO_CUSTOM_ACCESS, null, ROLE1},           //8
        });
    }

    @Test
    public void testInterceptShiroSecurity_PermitAll() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("permitAll");
        InvocationContext context = new TestInvocationContext(target, method);

        finishCDISetup();

        octopusInterceptor.interceptForSecurity(context);

        List<String> feedback = CallFeedbackCollector.getCallFeedback();
        assertThat(feedback).hasSize(1);
        assertThat(feedback).contains(MethodLevel.METHOD_LEVEL_PERMIT_ALL);
    }

    @Test(expected = SecurityViolationException.class)
    public void testInterceptShiroSecurity_NoAnnotation() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("noAnnotation");
        InvocationContext context = new TestInvocationContext(target, method);

        finishCDISetup();

        try {
            octopusInterceptor.interceptForSecurity(context);
        } finally {
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @Test
    public void testInterceptShiroSecurity_RequiresUser() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("requiresUser");
        InvocationContext context = new TestInvocationContext(target, method);

        finishCDISetup();

        try {
            octopusInterceptor.interceptForSecurity(context);

            assertThat(authenticated).isTrue();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevel.METHOD_LEVEL_REQUIRES_USER);

        } catch (SecurityViolationException e) {
            assertThat(authenticated).isFalse();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @Test
    public void testInterceptShiroSecurity_InAuthentication() throws Exception {

        // The in Authentication is so encapsulated that we can never set it outside the class (as we could manipulate then the security)
        // That is also the reason we have to simulate a larger part to test this.

        OctopusRealm octopusRealm = new OctopusRealm();

        when(octopusWebConfigurationMock.getHashAlgorithmName()).thenReturn("");

        /*
        FIXME
        TwoStepConfig twoStepConfigMock = Mockito.mock(TwoStepConfig.class);
        when(twoStepConfigMock.getAlwaysTwoStepAuthentication()).thenReturn(false);
        */

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("inAuthentication");
        InvocationContext context = new TestInvocationContext(target, method);

        when(authenticationInfoProviderHandlerMock.retrieveAuthenticationInfo(null)).thenAnswer(
                callInterceptorSimulatingAuthentication(context)
        );

        TestReflectionUtils.injectDependencies(octopusRealm, authenticationInfoProviderHandlerMock, octopusWebConfigurationMock/*, twoStepConfigMock*/);
        finishCDISetup();

        try {
            octopusRealm.getAuthenticationInfo(null);

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevel.METHOD_LEVEL_IN_AUTHENTICATION);

        } catch (SecurityViolationException e) {
            assertThat(authenticated).isTrue();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @Test
    public void testInterceptShiroSecurity_InAuthenticationDirect() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("inAuthentication");
        InvocationContext context = new TestInvocationContext(target, method);

        finishCDISetup();

        try {
            octopusInterceptor.interceptForSecurity(context);

            fail("We shouldn't be able to call the inAuthentication method as we aren't in the process of such an authentication");

        } catch (SecurityViolationException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @Test
    public void testInterceptShiroSecurity_InAuthorization() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("inAuthorization");
        InvocationContext context = new TestInvocationContext(target, method);

        // The in Authorization is so encapsulated that we can never set it outside the class (as we could manipulate then the security)
        // That is also the reason we have to simulate a larger part to test this.

        when(octopusConfigMock.isDynamicAuthorization()).thenReturn(false);
        OctopusRealm octopusRealm = new OctopusRealm();
        octopusRealm.setCachingEnabled(false);

        when(authorizationInfoProviderHandlerMock.retrieveAuthorizationInfo(ArgumentMatchers.any(PrincipalCollection.class))).thenAnswer(
                callInterceptorSimulatingAuthorization(context)
        );

        TestReflectionUtils.injectDependencies(octopusRealm, permissionResolverMock, authorizationInfoProviderHandlerMock, octopusConfigMock);
        finishCDISetup();

        try {
            octopusRealm.checkPermission(new SimplePrincipalCollection(), AUTHORIZATION_PERMISSION);

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevel.METHOD_LEVEL_IN_AUTHORIZATION);

        } catch (UnauthorizedException e) {
            assertThat(authenticated).isTrue();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @Test
    public void testInterceptShiroSecurity_InAuthorizationDirect() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("inAuthorization");
        InvocationContext context = new TestInvocationContext(target, method);

        finishCDISetup();

        try {
            octopusInterceptor.interceptForSecurity(context);

            fail("We shouldn't be able to call the inAuthorization method as we aren't in the process of such an authorization");

        } catch (SecurityViolationException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @Test
    public void testInterceptShiroSecurity_CustomPermissionAnnotation() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("permission1");
        InvocationContext context = new TestInvocationContext(target, method);

        GenericPermissionVoter permissionVoter = new GenericPermissionVoter();
        NamedDomainPermission namedPermission = getNamedDomainPermission(PERMISSION1);
        TestReflectionUtils.injectDependencies(permissionVoter, subjectMock, namedPermission);

        beanManagerFake.registerBean("permission1PermissionVoter", permissionVoter);

        PermissionLookupFixture.registerPermissionLookup(beanManagerFake);

        finishCDISetup();

        try {
            octopusInterceptor.interceptForSecurity(context);

            assertThat(permission).isEqualTo(PERMISSION1);
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevel.METHOD_LEVEL_PERMISSION1);

        } catch (SecurityViolationException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();

        }
    }

    @Test
    public void testInterceptShiroSecurity_CustomPermissionAnnotation2() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("permission2");
        InvocationContext context = new TestInvocationContext(target, method);

        GenericPermissionVoter permissionVoter = new GenericPermissionVoter();
        NamedDomainPermission namedPermission = getNamedDomainPermission(PERMISSION2);
        TestReflectionUtils.injectDependencies(permissionVoter, subjectMock, namedPermission);

        beanManagerFake.registerBean("permission2PermissionVoter", permissionVoter);

        PermissionLookupFixture.registerPermissionLookup(beanManagerFake);

        finishCDISetup();

        try {
            octopusInterceptor.interceptForSecurity(context);

            assertThat(permission).isEqualTo(PERMISSION2);
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevel.METHOD_LEVEL_PERMISSION2);

        } catch (SecurityViolationException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();

        }
    }

    @Test
    public void testInterceptShiroSecurity_CustomVoter() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("customVoter");
        InvocationContext context = new TestInvocationContext(target, method);

        finishCDISetup();

        try {
            octopusInterceptor.interceptForSecurity(context);

            assertThat(customAccess).isTrue();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevel.METHOD_LEVEL_CUSTOM_VOTER);

        } catch (SecurityViolationException e) {

            assertThat(customAccess).isFalse();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();

        }
    }

    @Test
    public void testInterceptShiroSecurity_RequiresPermission1() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("requiresPermission1");
        InvocationContext context = new TestInvocationContext(target, method);

        finishCDISetup();

        try {
            octopusInterceptor.interceptForSecurity(context);

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevel.METHOD_LEVEL_REQUIRES_PERMISSION1);

            assertThat(permission).isEqualTo(OCTOPUS1);

        } catch (SecurityViolationException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @Test
    public void testInterceptShiroSecurity_RequiresPermission2() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("requiresPermission2");
        InvocationContext context = new TestInvocationContext(target, method);

        finishCDISetup();

        try {
            octopusInterceptor.interceptForSecurity(context);

            fail("In our test, subject has never octopus2 permission");
        } catch (SecurityViolationException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @Test
    public void testInterceptShiroSecurity_SystemAccount1() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("systemAccountValue1");
        InvocationContext context = new TestInvocationContext(target, method);

        finishCDISetup();

        try {
            octopusInterceptor.interceptForSecurity(context);

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevel.METHOD_LEVEL_SYSTEM_ACCOUNT1);

            assertThat(systemAccount).isEqualTo(ACCOUNT1);
        } catch (SecurityViolationException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @Test
    public void testInterceptShiroSecurity_SystemAccount2() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("systemAccountValue2");
        InvocationContext context = new TestInvocationContext(target, method);

        finishCDISetup();

        try {
            octopusInterceptor.interceptForSecurity(context);

            fail("In our test, subject has never systemAccount 2");
        } catch (SecurityViolationException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @Test
    public void testInterceptShiroSecurity_OctopusPermission1() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("octopusPermission1");
        InvocationContext context = new TestInvocationContext(target, method);

        List<NamedDomainPermission> allPermissions = new ArrayList<>();
        allPermissions.add(new NamedDomainPermission("permissionName", NAMED_OCTOPUS));
        StringPermissionLookup lookup = new StringPermissionLookup(allPermissions);
        beanManagerFake.registerBean(lookup, StringPermissionLookup.class);
        //beanManagerFake.registerBean(new StringUtil(), StringUtil.class); FIXME

        finishCDISetup();

        securityCheckOctopusPermission.init();

        try {
            octopusInterceptor.interceptForSecurity(context);
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevel.METHOD_LEVEL_OCTOPUS_PERMISSION1);

            assertThat(permission).isEqualTo(NAMED_OCTOPUS);

        } catch (SecurityViolationException e) {
            // FIXME (and for all the other tests in this class) we need to check if the fail is ok.
            // We only test positive cases
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @Test
    public void testInterceptShiroSecurity_OctopusPermission3() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("octopusPermission3");
        InvocationContext context = new TestInvocationContext(target, method);

        finishCDISetup();

        securityCheckOctopusPermission.init();

        try {
            octopusInterceptor.interceptForSecurity(context);
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevel.METHOD_LEVEL_OCTOPUS_PERMISSION3);

            assertThat(permission).isIn(NAMED_OCTOPUS, OCTOPUS2);

        } catch (SecurityViolationException e) {
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @Test
    public void testInterceptShiroSecurity_OctopusPermission4() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("octopusPermission4");
        InvocationContext context = new TestInvocationContext(target, method);

        finishCDISetup();

        securityCheckOctopusPermission.init();

        try {
            octopusInterceptor.interceptForSecurity(context);
            // Should never be the case with the current setup of permissions
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevel.METHOD_LEVEL_OCTOPUS_PERMISSION3);

            assertThat(permission).isEqualTo(OCTOPUS2);

        } catch (SecurityViolationException e) {
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @Test
    public void testInterceptShiroSecurity_OctopusRole() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("octopusRole");
        InvocationContext context = new TestInvocationContext(target, method);

        finishCDISetup();
        securityCheckOctopusRole.init();
        securityCheckOctopusPermission.init();

        try {
            octopusInterceptor.interceptForSecurity(context);
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevel.METHOD_LEVEL_OCTOPUS_ROLE);

            assertThat(role).isEqualTo(ROLE1);

        } catch (SecurityViolationException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

}

