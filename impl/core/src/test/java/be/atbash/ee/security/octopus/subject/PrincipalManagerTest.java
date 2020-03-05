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
package be.atbash.ee.security.octopus.subject;

import be.atbash.ee.security.octopus.context.ThreadContext;
import be.atbash.ee.security.octopus.token.ValidatedAuthenticationToken;
import be.atbash.util.BeanManagerFake;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 *
 */
@ExtendWith(MockitoExtension.class)
public class PrincipalManagerTest {

    @Mock
    private Subject subjectMock;

    private BeanManagerFake beanManagerFake;

    private PrincipalManager principalManager;

    @BeforeEach
    public void init() {
        beanManagerFake = new BeanManagerFake();

        principalManager = new PrincipalManager();
    }

    @AfterEach
    public void teardown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void convert_fromPrincipalInstance() {

        beanManagerFake.endRegistration();

        ThreadContext.bind(subjectMock);

        PrincipalCollection principalCollection = new PrincipalCollection(new UserPrincipal(12L, "Atbash", "Atbash"));
        TestValidatedAuthenticationToken testToken = new TestValidatedAuthenticationToken();
        principalCollection.add(testToken);

        when(subjectMock.getPrincipals()).thenReturn(principalCollection);
        TestValidatedAuthenticationToken token = principalManager.convert(TestValidatedAuthenticationToken.class);

        assertThat(token).isSameAs(testToken);
    }

    @Test
    public void convert_preferPrincipalInstance() {
        TestValidatedAuthenticationToken converterTestToken = new TestValidatedAuthenticationToken();
        TestPrincipalConverter converter = new TestPrincipalConverter(converterTestToken);

        beanManagerFake.registerBean(converter, TestPrincipalConverter.class);
        beanManagerFake.endRegistration();

        ThreadContext.bind(subjectMock);

        PrincipalCollection principalCollection = new PrincipalCollection(new UserPrincipal(12L, "Atbash", "Atbash"));
        TestValidatedAuthenticationToken principalTestToken = new TestValidatedAuthenticationToken();
        principalCollection.add(principalTestToken);

        when(subjectMock.getPrincipals()).thenReturn(principalCollection);
        TestValidatedAuthenticationToken token = principalManager.convert(TestValidatedAuthenticationToken.class);

        assertThat(token).isSameAs(principalTestToken);
    }

    @Test
    public void convert_fromConverter() {
        TestValidatedAuthenticationToken converterTestToken = new TestValidatedAuthenticationToken();
        TestPrincipalConverter converter = new TestPrincipalConverter(converterTestToken);

        beanManagerFake.registerBean(converter, PrincipalConverter.class);
        beanManagerFake.endRegistration();

        principalManager.init(); // Get the converters

        ThreadContext.bind(subjectMock);

        PrincipalCollection principalCollection = new PrincipalCollection(new UserPrincipal(12L, "Atbash", "Atbash"));
        when(subjectMock.getPrincipals()).thenReturn(principalCollection);

        TestValidatedAuthenticationToken token = principalManager.convert(TestValidatedAuthenticationToken.class);

        assertThat(token).isSameAs(converterTestToken);
    }

    private static class TestValidatedAuthenticationToken implements ValidatedAuthenticationToken {

        @Override
        public Object getPrincipal() {
            return null;
        }

        @Override
        public Object getCredentials() {
            return null;
        }
    }

    private static class TestPrincipalConverter implements PrincipalConverter<TestValidatedAuthenticationToken> {

        private TestValidatedAuthenticationToken token;

        public TestPrincipalConverter(TestValidatedAuthenticationToken token) {
            this.token = token;
        }

        @Override
        public boolean supportFor(Class<TestValidatedAuthenticationToken> authenticationTokenClass) {
            return true;
        }

        @Override
        public TestValidatedAuthenticationToken convert(Subject subject) {
            return token;
        }
    }
}