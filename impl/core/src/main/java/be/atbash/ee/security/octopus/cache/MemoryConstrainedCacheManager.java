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
package be.atbash.ee.security.octopus.cache;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.util.cache.SoftHashMap;

/**
 * Simple memory-only based {@link CacheManager CacheManager} implementation usable in production
 * environments.  It will not cause memory leaks as it produces {@link Cache Cache}s backed by
 * {@link SoftHashMap SoftHashMap}s which auto-size themselves based on the runtime environment's memory
 * limitations and garbage collection behavior.
 * <p/>
 * While the {@code Cache} instances created are thread-safe, they do not offer any enterprise-level features such as
 * cache coherency, optimistic locking, failover or other similar features.  For more enterprise features, consider
 * using a different {@code CacheManager} implementation backed by an enterprise-grade caching product (Hazelcast,
 * EhCache, TerraCotta, Coherence, GigaSpaces, etc, etc).
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.cache.MemoryConstrainedCacheManager"})
public class MemoryConstrainedCacheManager extends AbstractCacheManager {

    /**
     * Returns a new {@link MapCache MapCache} instance backed by a {@link SoftHashMap}.
     *
     * @param name the name of the cache
     * @return a new {@link MapCache MapCache} instance backed by a {@link SoftHashMap}.
     */
    @Override
    protected Cache createCache(String name) {
        return new MapCache<>(name, new SoftHashMap<>());
    }
}
