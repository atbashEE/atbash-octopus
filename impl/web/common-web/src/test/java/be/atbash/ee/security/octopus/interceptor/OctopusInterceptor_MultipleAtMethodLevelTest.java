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

import be.atbash.ee.security.octopus.authz.permission.NamedDomainPermission;
import be.atbash.ee.security.octopus.authz.permission.typesafe.PermissionLookupFixture;
import be.atbash.ee.security.octopus.authz.permission.voter.GenericPermissionVoter;
import be.atbash.ee.security.octopus.authz.violation.SecurityAuthorizationViolationException;
import be.atbash.ee.security.octopus.interceptor.testclasses.MultipleAtMethodLevel;
import be.atbash.ee.security.octopus.realm.OctopusRealm;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.util.TestReflectionUtils;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import jakarta.interceptor.InvocationContext;
import java.lang.reflect.Method;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 *
 */
public class OctopusInterceptor_MultipleAtMethodLevelTest extends OctopusInterceptorTest {

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
    public void testInterceptShiroSecurity_InAuthentication(TestInterceptorParameters parameters) throws Exception {
        setup(parameters);

        // The in Authentication is so encapsulated that we can never set it outside the class (as we could manipulate then the security)
        // That is also the reason we have to simulate a larger part to test this.

        OctopusRealm octopusRealm = new OctopusRealm();

        when(octopusConfigMock.getHashAlgorithmName()).thenReturn("");

        /*
        TwoStepConfig twoStepConfigMock = Mockito.mock(TwoStepConfig.class);
        when(twoStepConfigMock.getAlwaysTwoStepAuthentication()).thenReturn(false);
        FIXME
        */

        TestReflectionUtils.injectDependencies(octopusRealm, authenticationInfoProviderHandlerMock, octopusConfigMock/*, twoStepConfigMock*/);
        registerPermissionVoter();

        Object target = new MultipleAtMethodLevel();
        Method method = target.getClass().getMethod("multiple");
        InvocationContext context = new TestInvocationContext(target, method);

        when(authenticationInfoProviderHandlerMock.retrieveAuthenticationInfo(any(AuthenticationToken.class))).thenAnswer(
                callInterceptorSimulatingAuthentication(context)
        );

        finishCDISetup();

        try {
            octopusRealm.getAuthenticationInfo(new SpecialValidatedToken());

            if (PERMISSION1.equals(parameters.getPermission())) {
                assertThat(parameters.isAuthenticated()).isTrue();
            }
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MultipleAtMethodLevel.MULTIPLE_CHECKS);

        } catch (SecurityAuthorizationViolationException e) {
            assertThat(parameters.isAuthenticated()).isTrue();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();
        }
    }

    @ParameterizedTest
    @MethodSource("provideArguments")
    public void testInterceptShiroSecurity_CustomPermissionAnnotation(TestInterceptorParameters parameters) throws Exception {
        setup(parameters);

        Object target = new MultipleAtMethodLevel();
        Method method = target.getClass().getMethod("multiple");
        InvocationContext context = new TestInvocationContext(target, method);

        registerPermissionVoter();

        PermissionLookupFixture.registerPermissionLookup(beanManagerFake);

        finishCDISetup();

        try {
            octopusInterceptor.interceptForSecurity(context);

            assertThat(parameters.getPermission()).isEqualTo(PERMISSION1);
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(MultipleAtMethodLevel.MULTIPLE_CHECKS);

        } catch (SecurityAuthorizationViolationException e) {

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

