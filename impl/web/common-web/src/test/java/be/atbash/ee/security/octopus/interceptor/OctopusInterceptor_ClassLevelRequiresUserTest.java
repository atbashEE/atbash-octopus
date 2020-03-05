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

import be.atbash.ee.security.octopus.authz.violation.SecurityAuthorizationViolationException;
import be.atbash.ee.security.octopus.interceptor.testclasses.ClassLevelRequiresUser;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.interceptor.InvocationContext;
import java.lang.reflect.Method;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */
public class OctopusInterceptor_ClassLevelRequiresUserTest extends OctopusInterceptorTest {

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
    public void testInterceptShiroSecurity_RequiresUser1(TestInterceptorParameters parameters) throws Exception {
        setup(parameters);

        Object target = new ClassLevelRequiresUser();
        Method method = target.getClass().getMethod("requiresUser1");
        InvocationContext context = new TestInvocationContext(target, method);

        performAndCheck(context, parameters);
    }

    private void performAndCheck(InvocationContext context, TestInterceptorParameters parameters) throws Exception {
        finishCDISetup();

        try {
            octopusInterceptor.interceptForSecurity(context);

            assertThat(parameters.isAuthenticated()).isTrue();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(ClassLevelRequiresUser.CLASS_LEVEL_REQUIRES_USER);

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
    public void testInterceptShiroSecurity_RequiresUser2(TestInterceptorParameters parameters) throws Exception {
        setup(parameters);

        Object target = new ClassLevelRequiresUser();
        Method method = target.getClass().getMethod("requiresUser2");
        InvocationContext context = new TestInvocationContext(target, method);

        performAndCheck(context, parameters);
    }

}

