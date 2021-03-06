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
package be.atbash.ee.security.octopus.interceptor;

import be.atbash.ee.security.octopus.authz.UnauthorizedException;
import be.atbash.ee.security.octopus.authz.permission.NamedDomainPermission;
import be.atbash.ee.security.octopus.authz.permission.StringPermissionLookup;
import be.atbash.ee.security.octopus.authz.permission.typesafe.PermissionLookupFixture;
import be.atbash.ee.security.octopus.authz.permission.voter.GenericPermissionVoter;
import be.atbash.ee.security.octopus.authz.violation.SecurityAuthorizationViolationException;
import be.atbash.ee.security.octopus.interceptor.testclasses.MethodLevel;
import be.atbash.ee.security.octopus.interceptor.testclasses.MethodLevelOverride;
import be.atbash.ee.security.octopus.realm.OctopusRealm;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.util.TestReflectionUtils;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.interceptor.InvocationContext;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 *
 */
public class OctopusInterceptor_MethodLevelOverrideTest extends OctopusInterceptorTest {

    private static Stream<Arguments> provideArguments() {
        return Stream.of(
                Arguments.of(new TestInterceptorParameters(NOT_AUTHENTICATED, null, NO_CUSTOM_ACCESS, null, null)),
                Arguments.of(new TestInterceptorParameters(NOT_AUTHENTICATED, null, CUSTOM_ACCESS, null, null)),
                Arguments.of(new TestInterceptorParameters(AUTHENTICATED, null, NO_CUSTOM_ACCESS, null, null)),
                Arguments.of(new TestInterceptorParameters(AUTHENTICATED, PERMISSION1, NO_CUSTOM_ACCESS, null, null)),
                Arguments.of(new TestInterceptorParameters(AUTHENTICATED, null, CUSTOM_ACCESS, null, null)),
                Arguments.of(new TestInterceptorParameters(AUTHENTICATED, OCTOPUS1, NO_CUSTOM_ACCESS, null, null)),
                Arguments.of(new TestInterceptorParameters(AUTHENTICATED, null, NO_CUSTOM_ACCESS, ACCOUNT1, null)),
                Arguments.of(new TestInterceptorParameters(AUTHENTICATED, null, NO_CUSTOM_ACCESS, null, ROLE1))
        );
    }

    @ParameterizedTest
    @MethodSource("provideArguments")
    public void testInterceptShiroSecurity_NoAnnotation(TestInterceptorParameters parameters) throws Exception {
        setup(parameters);

        Object target = new MethodLevelOverride();
        Method method = target.getClass().getMethod("noAnnotation");
        InvocationContext context = new TestInvocationContext(target, method);

        finishCDISetup();

        octopusInterceptor.interceptForSecurity(context);

        List<String> feedback = CallFeedbackCollector.getCallFeedback();
        assertThat(feedback).hasSize(1);
        assertThat(feedback).contains(MethodLevelOverride.METHOD_LEVEL_NO_ANNOTATION);
    }

    @ParameterizedTest
    @MethodSource("provideArguments")
    public void testInterceptShiroSecurity_RequiresUser(TestInterceptorParameters parameters) throws Exception {
        setup(parameters);

        Object target = new MethodLevelOverride();
        Method method = target.getClass().getMethod("requiresUser");
        InvocationContext context = new TestInvocationContext(target, method);

        finishCDISetup();

        try {
            octopusInterceptor.interceptForSecurity(context);

            assertThat(parameters.isAuthenticated()).isTrue();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevelOverride.METHOD_LEVEL_REQUIRES_USER);

        } catch (SecurityAuthorizationViolationException e) {
            if (parameters.getSystemAccount() == null) {
                assertThat(parameters.isAuthenticated()).isFalse();
            }
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @ParameterizedTest
    @MethodSource("provideArguments")
    public void testInterceptShiroSecurity_InAuthentication(TestInterceptorParameters parameters) throws Exception {
        setup(parameters);

        // The in Authentication is so encapsulated that we can never set it outside the class (as we could manipulate then the security)
        // That is also the reason we have to simulate a larger part to test this.

        OctopusRealm octopusRealm = new OctopusRealm();

        when(octopusConfigMock.getHashAlgorithmName()).thenReturn("");

        /*
        FIXME
        TwoStepConfig twoStepConfigMock = Mockito.mock(TwoStepConfig.class);
        when(twoStepConfigMock.getAlwaysTwoStepAuthentication()).thenReturn(false);
    */

        Object target = new MethodLevelOverride();
        Method method = target.getClass().getMethod("inAuthentication");
        InvocationContext context = new TestInvocationContext(target, method);

        when(authenticationInfoProviderHandlerMock.retrieveAuthenticationInfo(any(AuthenticationToken.class))).thenAnswer(
                callInterceptorSimulatingAuthentication(context)
        );

        TestReflectionUtils.injectDependencies(octopusRealm, authenticationInfoProviderHandlerMock, octopusConfigMock /*, twoStepConfigMock*/);

        //TestReflectionUtils.setFieldValue(octopusRealm, "octopusDefinedAuthenticationInfoList", new ArrayList()); FIXME? No longer needed
        finishCDISetup();

        try {
            octopusRealm.getAuthenticationInfo(new SpecialValidatedToken());

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevelOverride.METHOD_LEVEL_IN_AUTHENTICATION);

        } catch (SecurityAuthorizationViolationException e) {
            assertThat(parameters.isAuthenticated()).isTrue();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @ParameterizedTest
    @MethodSource("provideArguments")
    public void testInterceptShiroSecurity_InAuthenticationDirect(TestInterceptorParameters parameters) throws Exception {
        setup(parameters);

        Object target = new MethodLevelOverride();
        Method method = target.getClass().getMethod("inAuthentication");
        InvocationContext context = new TestInvocationContext(target, method);

        finishCDISetup();

        try {
            octopusInterceptor.interceptForSecurity(context);

            fail("We shouldn't be able to call the inAuthentication method as we aren't in the process of such an authentication");

        } catch (SecurityAuthorizationViolationException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @ParameterizedTest
    @MethodSource("provideArguments")
    public void testInterceptShiroSecurity_InAuthorization(TestInterceptorParameters parameters) throws Exception {
        setup(parameters);

        Object target = new MethodLevelOverride();
        Method method = target.getClass().getMethod("inAuthorization");
        InvocationContext context = new TestInvocationContext(target, method);

        // The in Authorization is so encapsulated that we can never set it outside the class (as we could manipulate then the security)
        // That is also the reason we have to simulate a larger part to test this.

        OctopusRealm octopusRealm = new OctopusRealm();
        octopusRealm.setCachingEnabled(false);

        when(authorizationInfoProviderHandlerMock.retrieveAuthorizationInfo(null)).thenAnswer(
                callInterceptorSimulatingAuthorization(context)
        );

        when(octopusConfigMock.isDynamicAuthorization()).thenReturn(false);
        TestReflectionUtils.injectDependencies(octopusRealm, permissionResolverMock, authorizationInfoProviderHandlerMock, octopusConfigMock);

        finishCDISetup();

        try {
            UserPrincipal userPrincipal = new UserPrincipal(123L, "Atbash", "Atbash");
            octopusRealm.checkPermission(new PrincipalCollection(userPrincipal), AUTHORIZATION_PERMISSION);

            fail("We are never in an authorization situation");
        } catch (UnauthorizedException e) {
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @ParameterizedTest
    @MethodSource("provideArguments")
    public void testInterceptShiroSecurity_InAuthorizationDirect(TestInterceptorParameters parameters) throws Exception {
        setup(parameters);

        Object target = new MethodLevelOverride();
        Method method = target.getClass().getMethod("inAuthorization");
        InvocationContext context = new TestInvocationContext(target, method);

        finishCDISetup();

        try {
            octopusInterceptor.interceptForSecurity(context);

            fail("We shouldn't be able to call the inAuthorization method as we aren't in the process of such an authorization");

        } catch (SecurityAuthorizationViolationException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @ParameterizedTest
    @MethodSource("provideArguments")
    public void testInterceptShiroSecurity_CustomPermissionAnnotation(TestInterceptorParameters parameters) throws Exception {
        setup(parameters);

        Object target = new MethodLevelOverride();
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

            assertThat(parameters.getPermission()).isEqualTo(PERMISSION1);
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevelOverride.METHOD_LEVEL_PERMISSION1);

        } catch (SecurityAuthorizationViolationException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();

        }
    }

    @ParameterizedTest
    @MethodSource("provideArguments")
    public void testInterceptShiroSecurity_CustomPermissionAnnotation2(TestInterceptorParameters parameters) throws Exception {
        setup(parameters);

        Object target = new MethodLevelOverride();
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

            assertThat(parameters.getPermission()).isEqualTo(PERMISSION2);
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevelOverride.METHOD_LEVEL_PERMISSION2);

        } catch (SecurityAuthorizationViolationException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();

        }
    }

    @ParameterizedTest
    @MethodSource("provideArguments")
    public void testInterceptShiroSecurity_CustomVoter(TestInterceptorParameters parameters) throws Exception {
        setup(parameters);

        Object target = new MethodLevelOverride();
        Method method = target.getClass().getMethod("customVoter");
        InvocationContext context = new TestInvocationContext(target, method);

        finishCDISetup();

        try {
            octopusInterceptor.interceptForSecurity(context);

            assertThat(parameters.isCustomAccess()).isTrue();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevelOverride.METHOD_LEVEL_CUSTOM_VOTER);

        } catch (SecurityAuthorizationViolationException e) {

            assertThat(parameters.isCustomAccess()).isFalse();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();

        }
    }

    @ParameterizedTest
    @MethodSource("provideArguments")
    public void testInterceptShiroSecurity_RequiresPermission1(TestInterceptorParameters parameters) throws Exception {
        setup(parameters);

        Object target = new MethodLevelOverride();
        Method method = target.getClass().getMethod("requiresPermission1");
        InvocationContext context = new TestInvocationContext(target, method);

        finishCDISetup();

        try {
            octopusInterceptor.interceptForSecurity(context);

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevelOverride.METHOD_LEVEL_REQUIRES_PERMISSION1);

            assertThat(parameters.getPermission()).isEqualTo(OCTOPUS1);

        } catch (SecurityAuthorizationViolationException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @ParameterizedTest
    @MethodSource("provideArguments")
    public void testInterceptShiroSecurity_RequiresPermission2(TestInterceptorParameters parameters) throws Exception {
        setup(parameters);

        Object target = new MethodLevelOverride();
        Method method = target.getClass().getMethod("requiresPermission2");
        InvocationContext context = new TestInvocationContext(target, method);

        finishCDISetup();

        try {
            octopusInterceptor.interceptForSecurity(context);

            fail("In our test, subject has never shiro2 permission");
        } catch (SecurityAuthorizationViolationException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @ParameterizedTest
    @MethodSource("provideArguments")
    public void testInterceptShiroSecurity_SystemAccount1(TestInterceptorParameters parameters) throws Exception {
        setup(parameters);

        Object target = new MethodLevelOverride();
        Method method = target.getClass().getMethod("systemAccountValue1");
        InvocationContext context = new TestInvocationContext(target, method);

        finishCDISetup();

        try {
            octopusInterceptor.interceptForSecurity(context);

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevelOverride.METHOD_LEVEL_SYSTEM_ACCOUNT1);

            assertThat(parameters.getSystemAccount()).isEqualTo(ACCOUNT1);

        } catch (SecurityAuthorizationViolationException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @ParameterizedTest
    @MethodSource("provideArguments")
    public void testInterceptShiroSecurity_OctopusPermission1(TestInterceptorParameters parameters) throws Exception {
        setup(parameters);

        Object target = new MethodLevelOverride();
        Method method = target.getClass().getMethod("octopusPermission1");
        InvocationContext context = new TestInvocationContext(target, method);

        List<NamedDomainPermission> allPermissions = new ArrayList<>();
        allPermissions.add(new NamedDomainPermission("permissionName", NAMED_OCTOPUS));
        StringPermissionLookup lookup = new StringPermissionLookup(allPermissions);
        beanManagerFake.registerBean(lookup, StringPermissionLookup.class);
        //beanManagerFake.registerBean(new StringUtil(), StringUtil.class); FIXME

        finishCDISetup();

        securityCheckRequiresPermissions.init();

        try {
            octopusInterceptor.interceptForSecurity(context);
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevel.METHOD_LEVEL_OCTOPUS_PERMISSION1);

            assertThat(parameters.getPermission()).isEqualTo(NAMED_OCTOPUS);

        } catch (SecurityAuthorizationViolationException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @ParameterizedTest
    @MethodSource("provideArguments")
    public void testInterceptShiroSecurity_OctopusRole(TestInterceptorParameters parameters) throws Exception {
        setup(parameters);

        Object target = new MethodLevelOverride();
        Method method = target.getClass().getMethod("octopusRole");
        InvocationContext context = new TestInvocationContext(target, method);

        finishCDISetup();
        securityCheckRequiresRoles.init();
        securityCheckRequiresPermissions.init();

        try {
            octopusInterceptor.interceptForSecurity(context);
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MethodLevel.METHOD_LEVEL_OCTOPUS_ROLE);

            assertThat(parameters.getRole()).isEqualTo(ROLE1);

        } catch (SecurityAuthorizationViolationException e) {

            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

}

