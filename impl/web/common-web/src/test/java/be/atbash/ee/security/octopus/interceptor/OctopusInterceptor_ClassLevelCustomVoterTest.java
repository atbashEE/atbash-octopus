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

import be.atbash.ee.security.octopus.authz.violation.SecurityViolationException;
import be.atbash.ee.security.octopus.interceptor.testclasses.ClassLevelCustomVoter;
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
public class OctopusInterceptor_ClassLevelCustomVoterTest extends OctopusInterceptorTest {

    public OctopusInterceptor_ClassLevelCustomVoterTest(boolean authenticated, String permission, boolean customAccess, String systemAccount, String role) {
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
                {AUTHENTICATED, null, NO_CUSTOM_ACCESS, ACCOUNT1, null},          //6
                {AUTHENTICATED, null, NO_CUSTOM_ACCESS, null, ROLE1},          //6
        });
    }

    @Test
    public void testInterceptShiroSecurity_CustomerVoter1() throws Exception {

        Object target = new ClassLevelCustomVoter();
        Method method = target.getClass().getMethod("customVoter1");
        InvocationContext context = new TestInvocationContext(target, method);

        performAndCheck(context);
    }

    private void performAndCheck(InvocationContext context) throws Exception {
        finishCDISetup();

        try {
            octopusInterceptor.interceptForSecurity(context);

            assertThat(customAccess).isTrue();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).hasSize(1);
            assertThat(feedback).contains(ClassLevelCustomVoter.CLASS_LEVEL_CUSTOM_VOTER);

        } catch (SecurityViolationException e) {

            assertThat(customAccess).isFalse();
            List<String> feedback = CallFeedbackCollector.getCallFeedback();
            assertThat(feedback).isEmpty();

        }
    }

    @Test
    public void testInterceptShiroSecurity_CustomVoter2() throws Exception {

        Object target = new ClassLevelCustomVoter();
        Method method = target.getClass().getMethod("customVoter2");
        InvocationContext context = new TestInvocationContext(target, method);

        performAndCheck(context);
    }

}

