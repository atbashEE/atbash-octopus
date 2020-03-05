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
package be.atbash.ee.security.octopus.otp.provider;

import be.atbash.ee.security.octopus.otp.OTPUserData;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */
public class TOTPProviderTest {

    private static final int OTP_LENGTH = 6;

    @Test
    public void generateTOTP() {

        byte[] key = createSecret();

        TOTPProvider provider = new TOTPProvider();
        settingProperties(provider);

        String value = provider.generate(getUserData(key));
        assertThat(value).hasSize(OTP_LENGTH);

        assertThat(value).containsOnlyDigits();
    }

    private void settingProperties(TOTPProvider provider) {
        Properties properties = new Properties();
        properties.setProperty("algorithm", "HmacSHA1");
        provider.setProperties(OTP_LENGTH, properties);
    }

    @Test
    public void generateTOTP_repeatable() {

        byte[] key = createSecret();

        TOTPProvider provider = new TOTPProvider();
        settingProperties(provider);

        String value1 = provider.generate(getUserData(key));

        provider = new TOTPProvider();
        settingProperties(provider);

        String value2 = provider.generate(getUserData(key));

        assertThat(value1).isEqualTo(value2);
        // Well, the above will fail now and then because we can just be over one time slot to another.

    }

    private OTPUserData getUserData(byte[] key) {
        return new OTPUserData(key, 0L);
    }

    private byte[] createSecret() {
        byte[] key = new byte[16];

        SecureRandom random = new SecureRandom();
        random.nextBytes(key);
        return key;
    }
    // TODO We need a mechanism to switch the times.
    // So that we can test the moving parts.

    @Test
    public void valid() {
        byte[] key = createSecret();

        TOTPProvider provider = new TOTPProvider();
        settingProperties(provider);

        String code = provider.generate(getUserData(key));

        provider = new TOTPProvider();
        settingProperties(provider);

        // Window = 1 ; Only valid values from previous window is allowed since this test method doesn't wait more then 30 sec.
        boolean valid = provider.valid(getUserData(key), 1, code);
        assertThat(valid).isTrue();
    }
}