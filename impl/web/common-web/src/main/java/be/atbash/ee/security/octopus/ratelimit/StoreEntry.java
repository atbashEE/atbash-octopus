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

import java.util.concurrent.atomic.AtomicInteger;

/**
 * StoreEntry implementation.
 * <p>
 * Modified from https://github.com/jabley/rate-limit created by James Abley (2009) Apache License, Version 2.0
 */
class StoreEntry {

    /**
     * The expiry time from the epoch.
     */
    private final long expiry;

    /**
     * The counter used to keep track of how many times the service has been used for the current period.
     */
    private final AtomicInteger counter;

    /**
     * Creates a new {@link StoreEntry} which will expire in {@code timeToLive} seconds.
     *
     * @param timeToLive the time to live in seconds
     */
    StoreEntry(int timeToLive) {
        expiry = System.currentTimeMillis() + timeToLive * 1000;
        counter = new AtomicInteger(0);
    }

    /**
     * Checks if this entry is expired or not (based on the timeToLive value).
     */
    boolean isExpired() {
        return System.currentTimeMillis() > expiry;
    }

    /**
     * Increment and get the counter in a ThreadSafe fashion.
     */
    int incrementAndGet() {
        return counter.incrementAndGet();
    }

}
