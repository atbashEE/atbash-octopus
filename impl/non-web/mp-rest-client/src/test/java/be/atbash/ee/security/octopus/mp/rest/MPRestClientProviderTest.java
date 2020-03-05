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
package be.atbash.ee.security.octopus.mp.rest;

import be.atbash.config.test.TestConfig;
import be.atbash.ee.security.octopus.context.ThreadContext;
import be.atbash.ee.security.octopus.jwt.encoder.JWTEncoder;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.generator.RSAGenerationParameters;
import be.atbash.ee.security.octopus.keys.selector.KeySelector;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.ee.security.octopus.mp.token.MPJWTToken;
import be.atbash.ee.security.octopus.mp.token.MPToken;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.util.BeanManagerFake;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.core.MultivaluedHashMap;
import java.io.IOException;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 *
 */
@ExtendWith(MockitoExtension.class)
public class MPRestClientProviderTest {

    private static AtbashKey key1;

    @Mock
    private ClientRequestContext clientRequestContextMock;

    @Mock
    private Subject subjectMock;

    @Mock
    private JWTEncoder jwtEncoderMock;

    @Mock
    private KeySelector keySelectorMock;

    @Captor
    private ArgumentCaptor<SelectorCriteria> selectorCriteriaArgumentCaptor;

    private BeanManagerFake beanManagerFake;

    private MPRestClientProvider provider;

    private MultivaluedHashMap<String, Object> headers = new MultivaluedHashMap<>();

    private MPJWTToken token = new MPJWTToken();

    @BeforeAll
    public static void defineKeys() {
        RSAGenerationParameters generationParameters = new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeyId("kid")
                .build();
        KeyGenerator generator = new KeyGenerator();
        List<AtbashKey> keys = generator.generateKeys(generationParameters);

        key1 = keys.get(0); // It doesn't really matter, but we just need a value
    }

    @BeforeEach
    public void setup() {
        provider = new MPRestClientProvider();
        ThreadContext.bind(subjectMock);

        PrincipalCollection collection = new PrincipalCollection(new UserPrincipal(123L, "Atbash", "Atbash"));

        collection.add(new MPToken(token));
        when(subjectMock.getPrincipals()).thenReturn(collection);

        beanManagerFake = new BeanManagerFake();
        beanManagerFake.registerBean(jwtEncoderMock, JWTEncoder.class);
        beanManagerFake.registerBean(keySelectorMock, KeySelector.class);

        when(jwtEncoderMock.encode(any(), any(JWTParameters.class))).thenReturn("jwtHeader");

        when(clientRequestContextMock.getHeaders()).thenReturn(headers);

        TestConfig.registerDefaultConverters();
    }

    @AfterEach
    public void teardown() {
        beanManagerFake.deregistration();
        TestConfig.resetConfig();
    }

    @Test
    public void filter_somePrivatePartKey() throws IOException {
        when(keySelectorMock.selectAtbashKey(any(SelectorCriteria.class))).thenReturn(key1);

        provider.filter(clientRequestContextMock);

        assertThat(headers).hasSize(1);
        assertThat(headers).containsKey("authorization");
        assertThat(headers).containsValue(Collections.<Object>singletonList("Bearer jwtHeader"));

        verify(keySelectorMock).selectAtbashKey(selectorCriteriaArgumentCaptor.capture());

        SelectorCriteria selectorCriteria = selectorCriteriaArgumentCaptor.getValue();
        assertThat(selectorCriteria.getId()).isNull();
        assertThat(selectorCriteria.getAsymmetricPart()).isNotNull();
    }

    @Test
    public void filter_useSpecificKeyWithId() throws IOException {
        TestConfig.addConfigValue("mp.key.id", "specificKey");
        when(keySelectorMock.selectAtbashKey(any(SelectorCriteria.class))).thenReturn(key1);

        provider.filter(clientRequestContextMock);

        assertThat(headers).hasSize(1);
        assertThat(headers).containsKey("authorization");
        assertThat(headers).containsValue(Collections.<Object>singletonList("Bearer jwtHeader"));

        verify(keySelectorMock).selectAtbashKey(selectorCriteriaArgumentCaptor.capture());

        SelectorCriteria selectorCriteria = selectorCriteriaArgumentCaptor.getValue();
        assertThat(selectorCriteria.getId()).isEqualTo("specificKey");
        assertThat(selectorCriteria.getAsymmetricPart()).isNull();
    }
}