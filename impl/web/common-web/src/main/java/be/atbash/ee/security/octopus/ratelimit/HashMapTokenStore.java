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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * {@link TokenStore} implementation that is purely in-memory.
 * <p>
 * Modified from https://github.com/jabley/rate-limit created by James Abley (2009) Apache License, Version 2.0
 */
public class HashMapTokenStore implements TokenStore {

    /**
     * The Map used to keep track of {@link StoreEntry} instances.
     */
    private final Map<String, StoreEntry> cache;

    /**
     * The {@link Lock} used to guard reads.
     */
    private final Lock r;

    /**
     * The {@link Lock} used to guard writes.
     */
    private final Lock w;

    /**
     * Creates a new {@link HashMapTokenStore}.
     */
    public HashMapTokenStore() {
        this.cache = new ConcurrentHashMap<>();
        ReadWriteLock lock = new ReentrantReadWriteLock();
        this.r = lock.readLock();
        this.w = lock.writeLock();
    }

    /**
     * {@inheritDoc}
     */
    public StoreEntry get(String key) {
        StoreEntry result;
        r.lock();

        try {
            result = this.cache.get(key);
        } finally {
            r.unlock();
        }

        if (!(result == null || result.isExpired())) {

            /* Cache hit with a good entry - use it. */
            return result;
        }

        w.lock();

        result = checkPopulateThisPeriod(key);

        return result;
    }

    /**
     * {@inheritDoc}
     */
    public StoreEntry create(String key, int timeToLive) {
        try {
            StoreEntry entry = new StoreEntry(timeToLive);
            cache.put(key, entry);
            return entry;
        } finally {
            w.unlock();
        }
    }

    /**
     * If no usable entry in the cache, then we assume that the write lock is held prior to calling this method.
     * <p>
     * Returns null to indicate that the context client thread is safe to call {@link #create(String, int)}, otherwise
     * returns a usable {@link StoreEntry}.
     *
     * @param key the non-null key
     * @return a {@link StoreEntry} - may be null
     */
    private StoreEntry checkPopulateThisPeriod(String key) {

        /* Check the cache again in case it got updated by a different thread. */
        StoreEntry result = this.cache.get(key);

        if (result == null) {

            /* Keep the write lock and expect that the client will call create(Key, int) very soon. */
        } else if (result.isExpired()) {

            /*
             * Remove the expired lock and signal to the client that they are the first one in the new period. Keep the
             * write lock in the expectation that the client will call create(Key, int),
             */
            cache.remove(key);
            result = null;
        } else {

            /*
             * A different thread won and populated it already. Release the write lock and return the good non-null
             * result.
             */
            w.unlock();
        }

        return result;
    }

}