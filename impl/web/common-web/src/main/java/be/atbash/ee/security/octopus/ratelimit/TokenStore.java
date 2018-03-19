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

/**
 * Interface defining how {@link StoreEntry}s are managed.
 * TODO Allow implementation to be defined so that we can have a rate limit in a clustered environment.
 * Modified from https://github.com/jabley/rate-limit created by James Abley (2009) Apache License, Version 2.0
 */
public interface TokenStore {

    /**
     * Returns a usable {@link StoreEntry} for the given key. A value of {@code null} means that there is no
     * such {@link StoreEntry} and the calling client <strong>MUST</strong> call {@link #create(String, int)} to avoid
     * other clients potentially being blocked without any hope of progressing. By usable, it is meant that the non-null
     * {@link StoreEntry} has not expired and can be used to determine whether the current client should be allowed to
     * proceed with the rate-limited action or not.
     *
     * @param key the non-null key
     * @return a {@link StoreEntry} or null
     */
    StoreEntry get(String key);

    /**
     * Creates a new {@link StoreEntry}
     *
     * @param key              the non-null key
     * @param timeToLiveInSecs the positive time-to-live in seconds
     * @return a non-null usable {@link StoreEntry}
     */
    StoreEntry create(String key, int timeToLiveInSecs);

}
