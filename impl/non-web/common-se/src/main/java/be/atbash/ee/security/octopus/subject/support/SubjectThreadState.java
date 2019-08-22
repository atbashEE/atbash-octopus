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
package be.atbash.ee.security.octopus.subject.support;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.context.ThreadContext;
import be.atbash.ee.security.octopus.mgt.StandardSecurityManager;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.ee.security.octopus.util.ThreadState;
import be.atbash.util.CollectionUtils;

import java.util.Map;

/**
 * Manages thread-state for {@link Subject Subject} access (supporting
 * {@code SecurityUtils.}{@link be.atbash.ee.security.octopus.SecurityUtils#getSubject() getSubject()} calls)
 * during a thread's execution.
 * <p/>
 * The {@link #bind bind} method will bind a {@link Subject} and a
 * {@link SecurityManager SecurityManager} to the {@link WebThreadContext} so they can be retrieved
 * from the {@code ThreadContext} later by any
 * {@code SecurityUtils.}{@link be.atbash.ee.security.octopus.SecurityUtils#getSubject() getSubject()} calls that might occur during
 * the thread's execution.
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.subject.support.SubjectThreadState"})
// TODO Check usage within the runAs
public class SubjectThreadState implements ThreadState {

    private Map<Object, Object> originalResources;

    private final Subject subject;
    private transient StandardSecurityManager securityManager;

    /**
     * Creates a new {@code SubjectThreadState} that will bind and unbind the specified {@code Subject} to the
     * thread
     *
     * @param subject the {@code Subject} instance to bind and unbind from the {@link WebThreadContext}.
     */
    public SubjectThreadState(Subject subject) {
        if (subject == null) {
            throw new IllegalArgumentException("Subject argument cannot be null.");
        }
        this.subject = subject;

        // FIXME
        throw new UnsupportedOperationException("Implement be.atbash.ee.security.octopus.subject.support.SubjectThreadState.SubjectThreadState");
        /*
        WebSecurityManager securityManager = subject.getSecurityManager();

        if (securityManager == null) {
            securityManager = ThreadContext.getSecurityManager();
        }
        this.securityManager = securityManager;
        */
    }

    /**
     * Returns the {@code Subject} instance managed by this {@code ThreadState} implementation.
     *
     * @return the {@code Subject} instance managed by this {@code ThreadState} implementation.
     */
    protected Subject getSubject() {
        return subject;
    }

    /**
     * Binds a {@link Subject} and {@link SecurityManager SecurityManager} to the
     * {@link WebThreadContext} so they can be retrieved later by any
     * {@code SecurityUtils.}{@link be.atbash.ee.security.octopus.SecurityUtils#getSubject() getSubject()} calls that might occur
     * during the thread's execution.
     * <p/>
     * Prior to binding, the {@code ThreadContext}'s existing {@link WebThreadContext#getResources() resources} are
     * retained so they can be restored later via the {@link #restore restore} call.
     */
    public void bind() {
        // FIXME
        throw new UnsupportedOperationException("Implement be.atbash.ee.security.octopus.subject.support.SubjectThreadState.bind");
        /*
        WebSecurityManager securityManager = this.securityManager;
        if (securityManager == null) {
            //try just in case the constructor didn't find one at the time:
            securityManager = WebThreadContext.getSecurityManager();
        }
        originalResources = WebThreadContext.getResources();
        ThreadContext.remove();

        ThreadContext.bind(subject);
        if (securityManager != null) {
            ThreadContext.bind(securityManager);
        }
        */
    }

    /**
     * {@link WebThreadContext#remove Remove}s all thread-state that was bound by this instance.  If any previous
     * thread-bound resources existed prior to the {@link #bind bind} call, they are restored back to the
     * {@code ThreadContext} to ensure the thread state is exactly as it was before binding.
     */
    public void restore() {
        ThreadContext.remove();
        if (!CollectionUtils.isEmpty(originalResources)) {
            ThreadContext.setResources(originalResources);
        }
    }

    /**
     * Completely {@link WebThreadContext#remove removes} the {@code ThreadContext} state.  Typically this method should
     * only be called in special cases - it is more 'correct' to {@link #restore restore} a thread to its previous
     * state than to clear it entirely.
     */
    public void clear() {
        ThreadContext.remove();
    }
}
