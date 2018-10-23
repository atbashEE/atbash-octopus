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
package be.atbash.ee.security.octopus.util.duration;

import be.atbash.config.exception.ConfigurationException;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class PeriodUtilTest {

    @Test
    public void defineSecondsInPeriod_sec() {

        assertThat(PeriodUtil.defineSecondsInPeriod("3s")).isEqualTo(3);
    }

    @Test
    public void defineSecondsInPeriod_min() {

        assertThat(PeriodUtil.defineSecondsInPeriod("7m")).isEqualTo(7 * 60);
    }

    @Test
    public void defineSecondsInPeriod_hour() {

        assertThat(PeriodUtil.defineSecondsInPeriod("1h")).isEqualTo(3600);
    }

    @Test(expected = ConfigurationException.class)
    public void defineSecondsInPeriod_empty() {

        PeriodUtil.defineSecondsInPeriod("");

    }

    @Test(expected = ConfigurationException.class)
    public void defineSecondsInPeriod_null() {

        PeriodUtil.defineSecondsInPeriod(null);

    }

    @Test(expected = ConfigurationException.class)
    public void defineSecondsInPeriod_mixed() {

        PeriodUtil.defineSecondsInPeriod("3m10s");

    }
}