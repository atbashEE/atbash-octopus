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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 *
 */

public final class PeriodUtil {

    private static final Pattern PERIOD_PATTERN = Pattern.compile("(\\d+)([smh])");

    private PeriodUtil() {
    }

    public static int defineSecondsInPeriod(String periodConfig) {
        if (periodConfig == null) {
            throw new ConfigurationException(String.format("Period configuration '%s' is not valid, see documentation", periodConfig));
        }
        Matcher matcher = PERIOD_PATTERN.matcher(periodConfig);
        if (!matcher.matches()) {
            throw new ConfigurationException(String.format("Period configuration '%s' is not valid, see documentation", periodConfig));
        }

        String timeUnit = matcher.group(2);
        int result = -1;
        if ("s".equals(timeUnit)) {
            result = Integer.valueOf(matcher.group(1));
        }
        if ("m".equals(timeUnit)) {
            result = Integer.valueOf(matcher.group(1)) * 60;
        }
        if ("h".equals(timeUnit)) {
            result = Integer.valueOf(matcher.group(1)) * 3600;
        }

        return result;
    }
}
