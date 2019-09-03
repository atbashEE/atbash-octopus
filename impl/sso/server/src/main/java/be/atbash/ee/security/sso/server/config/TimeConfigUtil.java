/*
 * Copyright 2014-2019 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.sso.server.config;

import be.atbash.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class TimeConfigUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(TimeConfigUtil.class);

    private TimeConfigUtil() {
    }

    public static int getSecondsFromConfigPattern(String data, String defaultConfig, String paramaterName) {
        Pattern pattern = Pattern.compile("^(\\d+)([Mdhms])$");

        String config = data;
        if (StringUtils.isEmpty(data)) {
            config = defaultConfig;
        }

        Matcher matcher = pattern.matcher(config);

        int result = 0;
        if (matcher.matches()) {

            // Seconds
            if ("s".equalsIgnoreCase(matcher.group(2))) {
                result = Integer.parseInt(matcher.group(1));
            }

            // Minutes
            if ("m".equalsIgnoreCase(matcher.group(2))) {
                result = Integer.parseInt(matcher.group(1)) * 60;
            }

            // Hour
            if ("h".equalsIgnoreCase(matcher.group(2))) {
                result = Integer.parseInt(matcher.group(1)) * 60 * 60;
            }

            // Day
            if ("d".equalsIgnoreCase(matcher.group(2))) {
                result = Integer.parseInt(matcher.group(1)) * 24 * 60 * 60;
            }


            if (!(result > 0)) {
                LOGGER.warn(String.format("Invalid configuration value for %s = %s. Using default of %s", paramaterName, data, defaultConfig));
                result = getSecondsFromConfigPattern(defaultConfig, defaultConfig, paramaterName);
            }

        } else {
            LOGGER.warn(String.format("Invalid configuration value for %s = %s. Using default of %s", paramaterName, data, defaultConfig));
            result = getSecondsFromConfigPattern(defaultConfig, defaultConfig, paramaterName);
        }
        return result;
    }
}