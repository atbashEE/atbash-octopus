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
package be.atbash.ee.security.octopus.ratelimit;

import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */
public class RateLimitConfigTest {

    private RateLimitConfig config;

    @Test
    public void createRateLimiter_seconds() {
        config = new RateLimitConfig();
        FixedBucket rateLimiter = config.createRateLimiter("10/1s");

        assertThat(rateLimiter).isNotNull();
        assertThat(rateLimiter.getDuration()).isEqualTo(1);
        assertThat(rateLimiter.getAllowedRequests()).isEqualTo(10);
    }

    @Test
    public void createRateLimiter_minutes() {
        config = new RateLimitConfig();
        FixedBucket rateLimiter = config.createRateLimiter("1000/5m");

        assertThat(rateLimiter).isNotNull();
        assertThat(rateLimiter.getDuration()).isEqualTo(300);
        assertThat(rateLimiter.getAllowedRequests()).isEqualTo(1000);
    }

    @Test
    public void createRateLimiter_hours() {
        config = new RateLimitConfig();
        FixedBucket rateLimiter = config.createRateLimiter("100000/1h");

        assertThat(rateLimiter).isNotNull();
        assertThat(rateLimiter.getDuration()).isEqualTo(3600);
        assertThat(rateLimiter.getAllowedRequests()).isEqualTo(100000);
    }

    @Test(expected = ConfigurationException.class)
    public void createRateLimiter_MissingTimeValue() {
        config = new RateLimitConfig();
        config.createRateLimiter("1000/s");

    }

}