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
package be.atbash.ee.security.octopus.mp.token;

import be.atbash.ee.security.octopus.mp.config.MPCoreConfiguration;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class MPJWTTokenBuilderTest {

    @Mock
    private MPCoreConfiguration configurationMock;

    @InjectMocks
    private MPJWTTokenBuilder tokenBuilder;

    @BeforeEach
    public void setup() {
        tokenBuilder.init();
    }

    @Test
    public void build() {

        Date now = new Date();
        Date exp = new Date(now.getTime() + 30 * 60 * 1000);

        tokenBuilder.setIssuer("ISS");
        tokenBuilder.setAudience("AUD");
        tokenBuilder.setIssuedAtTime(now);
        tokenBuilder.setExpirationTime(exp);
        tokenBuilder.setSubject("Subject");

        MPJWTToken token = tokenBuilder.build();

        assertThat(token.getIss()).isEqualTo("ISS");
        assertThat(token.getAud()).isEqualTo("AUD");
        assertThat(token.getIat()).isEqualTo(now.getTime());
        assertThat(token.getExp()).isEqualTo(exp.getTime());

        assertThat(token.getSub()).isEqualTo("Subject");
        assertThat(token.getUpn()).isEqualTo("Subject");

    }

    @Test
    public void build_setExpirationPeriod() {

        Date now = new Date();

        tokenBuilder.setIssuer("ISS");
        tokenBuilder.setAudience("AUD");
        tokenBuilder.setIssuedAtTime(now);
        tokenBuilder.setExpirationPeriod("2m");
        tokenBuilder.setSubject("Subject");


        MPJWTToken token = tokenBuilder.build();

        assertThat(token.getIss()).isEqualTo("ISS");
        assertThat(token.getAud()).isEqualTo("AUD");
        assertThat(token.getIat()).isEqualTo(now.getTime());

        assertThat(token.getExp()).isGreaterThanOrEqualTo(token.getIat() + 2 * 60 * 1000);
        // 0.2 sec skew
        assertThat(token.getExp() - 200).isLessThan(token.getIat() + 2 * 60 * 1000);

        assertThat(token.getSub()).isEqualTo("Subject");
        assertThat(token.getUpn()).isEqualTo("Subject");

    }

    @Test
    public void build_defaults() {

        when(configurationMock.getIssuer()).thenReturn("SSI");
        when(configurationMock.getAudience()).thenReturn("DUA");
        when(configurationMock.getExpirationTime()).thenReturn("3s");

        Date now = new Date();
        tokenBuilder.setSubject("tcejbuS");

        MPJWTToken token = tokenBuilder.build();

        assertThat(token.getIss()).isEqualTo("SSI");
        assertThat(token.getAud()).isEqualTo("DUA");
        assertThat(token.getIat() - now.getTime()).isLessThan(100);// Faster then 0.1 sec
        assertThat(token.getExp()).isEqualTo(token.getIat() + 3 * 1000);

        assertThat(token.getSub()).isEqualTo("tcejbuS");
        assertThat(token.getUpn()).isEqualTo("tcejbuS");

    }

    @Test
    public void build_missingIss() {

        Date now = new Date();
        Date exp = new Date(now.getTime() + 30 * 60 * 1000);

        tokenBuilder.setAudience("AUD");
        tokenBuilder.setIssuedAtTime(now);
        tokenBuilder.setExpirationTime(exp);
        tokenBuilder.setSubject("Subject");


        MissingClaimMPJWTTokenException exception = Assertions.assertThrows(MissingClaimMPJWTTokenException.class, () -> tokenBuilder.build());
        assertThat(exception.getMessage()).contains("'iss'");
    }

    @Test
    public void build_missingAud() {
        Date now = new Date();
        Date exp = new Date(now.getTime() + 30 * 60 * 1000);

        tokenBuilder.setIssuer("ISS");
        tokenBuilder.setIssuedAtTime(now);
        tokenBuilder.setExpirationTime(exp);
        tokenBuilder.setSubject("Subject");

        MissingClaimMPJWTTokenException exception = Assertions.assertThrows(MissingClaimMPJWTTokenException.class, () -> tokenBuilder.build());
        assertThat(exception.getMessage()).contains("'aud'");


    }

    @Test
    public void Build_missingExp() {

        tokenBuilder.setIssuer("ISS");
        tokenBuilder.setAudience("AUD");
        tokenBuilder.setSubject("Subject");

        MissingClaimMPJWTTokenException exception = Assertions.assertThrows(MissingClaimMPJWTTokenException.class, () -> tokenBuilder.build());
        assertThat(exception.getMessage()).contains("'exp'");

    }

    @Test
    public void build_missingSubUpn() {
        Date now = new Date();
        Date exp = new Date(now.getTime() + 30 * 60 * 1000);


        tokenBuilder.setIssuer("ISS");
        tokenBuilder.setAudience("AUD");
        tokenBuilder.setIssuedAtTime(now);
        tokenBuilder.setExpirationTime(exp);

        MissingClaimMPJWTTokenException exception = Assertions.assertThrows(MissingClaimMPJWTTokenException.class, () -> tokenBuilder.build());
        assertThat(exception.getMessage()).contains("'sub' and 'upn'");

    }

}
