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

import be.atbash.ee.security.octopus.otp.OTPProvider;
import org.junit.jupiter.api.Test;

import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */
public class SOTPProviderTest {

    private static final int OTP_LENGTH = 6;

    @Test
    public void generate() {
        SOTPProvider provider = new SOTPProvider();
        configure(provider);
        String value = provider.generate(null);
        assertThat(value).hasSize(OTP_LENGTH);
    }

    private void configure(OTPProvider provider) {
        provider.setProperties(OTP_LENGTH, new Properties());
    }

    @Test
    public void generate_noDoubles() {
        SOTPProvider provider = new SOTPProvider();
        configure(provider);
        String value1 = provider.generate(null);
        String value2 = provider.generate(null);

        assertThat(value1).isNotEqualTo(value2);
    }

}