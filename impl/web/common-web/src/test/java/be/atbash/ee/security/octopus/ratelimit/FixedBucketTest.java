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

import org.junit.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Modified from https://github.com/jabley/rate-limit created by James Abley (2009) Apache License, Version 2.0
 */

public class FixedBucketTest {
    @Test
    public void sequentialFixedBucketAccess() {
        FixedBucket rateLimiter = new FixedBucket();
        int allowedRequests = 1;
        rateLimiter.setAllowedRequests(allowedRequests);
        rateLimiter.setTokenStore(createTokenStore());

        String key = "TestKey";

        Token token = rateLimiter.getToken(key);
        assertThat(token.isUsable()).as("We have a usable token back for the first request").isTrue();

        token = rateLimiter.getToken(key);

        assertThat(token.isUsable()).as("The second token is not usable, since we assume that the two token"
                + " accesses take less than a second to perform").isFalse();
    }

    @Test
    public void multipleKeyFixedBucketAccess() {
        FixedBucket rateLimiter = new FixedBucket();
        int allowedRequests = 1;
        rateLimiter.setAllowedRequests(allowedRequests);
        rateLimiter.setTokenStore(createTokenStore());

        String key1 = "TestKey1";
        String key2 = "TestKey2";

        Token token = rateLimiter.getToken(key1);
        assertThat(token.isUsable()).as("We have a usable token back for the first request").isTrue();

        token = rateLimiter.getToken(key1);
        assertThat(token.isUsable()).as("The second token is not usable, since we assume that the two token"
                + " accesses take less than a second to perform").isFalse();

        token = rateLimiter.getToken(key2);
        assertThat(token.isUsable()).as("We have a usable token back for the first request of the second key").isTrue();
    }

    @Test
    public void canDoReasonableNumberOfTokenChecksPerSecond() throws Exception {
        FixedBucket rateLimiter = new FixedBucket();
        int allowedRequests = 50000;
        rateLimiter.setAllowedRequests(allowedRequests);
        rateLimiter.setTokenStore(createTokenStore());

        String key = "TestKey";

        Token token;
        int n = allowedRequests;
        for (int i = 0; i < n; ++i) {
            token = rateLimiter.getToken(key);
            assertThat(token.isUsable()).as("We have a usable token back for the first request").isTrue();
        }

        token = rateLimiter.getToken(key);

        assertThat(token.isUsable()).as("The current token is not usable, since we assume that the %s token"
                + " accesses take less than a second to perform", allowedRequests).isFalse();
    }

    @Test
    public void multipleClientsCanAccessWithoutBlocking() throws Exception {
        final FixedBucket rateLimiter = new FixedBucket();
        int allowedRequests = 200;
        rateLimiter.setAllowedRequests(allowedRequests);
        rateLimiter.setTokenStore(createTokenStore());

        final String key = "TestKey";

        Runnable[] clients = new Runnable[allowedRequests];
        final boolean[] isUsable = new boolean[allowedRequests];

        final CountDownLatch startGate = new CountDownLatch(1);

        final CountDownLatch endGate = new CountDownLatch(allowedRequests);

        for (int i = 0, n = isUsable.length; i < n; ++i) {
            final int j = i;
            clients[j] = new Runnable() {

                /**
                 * {@inheritDoc}
                 */
                public void run() {
                    try {
                        startGate.await();

                        isUsable[j] = rateLimiter.getToken(key).isUsable();

                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    } finally {
                        endGate.countDown();
                    }
                }
            };
        }

        ExecutorService executor = Executors.newFixedThreadPool(allowedRequests);

        for (Runnable runnable : clients) {
            executor.execute(runnable);
        }

        startGate.countDown();

        endGate.await();

        for (boolean b : isUsable) {
            assertThat(b).isTrue();
        }
    }

    @Test
    public void expiryOfTokensIsSupported() throws Exception {
        FixedBucket rateLimiter = new FixedBucket();
        int allowedRequests = 1;
        rateLimiter.setAllowedRequests(allowedRequests);
        rateLimiter.setTokenStore(createTokenStore());
        rateLimiter.setDuration(1);

        String key = "TestKey";

        Token token = rateLimiter.getToken(key);
        assertThat(token.isUsable()).as("We have a usable token back for the first request").isTrue();

        // Allow the token to expire
        Thread.sleep(1001);

        token = rateLimiter.getToken(key);
        assertThat(token.isUsable()).as("We have a usable token back for the second request").isTrue();

    }

    private TokenStore createTokenStore() {
        return new HashMapTokenStore();
    }

}