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
package be.atbash.ee.security.octopus.context;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.mgt.WebSecurityManager;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.util.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * A ThreadContext provides a means of binding and unbinding objects to the
 * current thread based on key/value pairs.
 * <p/>
 * <p>An internal {@link HashMap} is used to maintain the key/value pairs
 * for each thread.</p>
 * <p/>
 * <p>If the desired behavior is to ensure that bound data is not shared across
 * threads in a pooled or reusable threaded environment, the application (or more likely a framework) must
 * bind and remove any necessary values at the beginning and end of stack
 * execution, respectively (i.e. individually explicitly or all via the <tt>clear</tt> method).</p>
 *
 * @see #remove()
 */
// FIXME Use non Web based version???
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.util.ThreadContext"})
public abstract class WebThreadContext extends ThreadContext {

    /**
     * Private internal log instance.
     */
    private static final Logger log = LoggerFactory.getLogger(WebThreadContext.class);

    public static final String SECURITY_MANAGER_KEY = WebThreadContext.class.getName() + "_SECURITY_MANAGER_KEY";
    public static final String SUBJECT_KEY = WebThreadContext.class.getName() + "_SUBJECT_KEY";

    // FIXME Also in parent class.
    private static final ThreadLocal<Map<Object, Object>> resources = new InheritableThreadLocalMap<>();

    /**
     * Default no-argument constructor.
     */
    protected WebThreadContext() {
    }

    /**
     * Returns the ThreadLocal Map. This Map is used internally to bind objects
     * to the current thread by storing each object under a unique key.
     *
     * @return the map of bound resources
     */
    public static Map<Object, Object> getResources() {
        return new HashMap<>(resources.get());
    }

    /**
     * Allows a caller to explicitly set the entire resource map.  This operation overwrites everything that existed
     * previously in the ThreadContext - if you need to retain what was on the thread prior to calling this method,
     * call the {@link #getResources()} method, which will give you the existing state.
     *
     * @param newResources the resources to replace the existing {@link #getResources() resources}.
     */
    public static void setResources(Map<Object, Object> newResources) {
        if (CollectionUtils.isEmpty(newResources)) {
            return;
        }
        resources.get().clear();
        resources.get().putAll(newResources);
    }

    /**
     * Returns the value bound in the {@code ThreadContext} under the specified {@code key}, or {@code null} if there
     * is no value for that {@code key}.
     *
     * @param key the map key to use to lookup the value
     * @return the value bound in the {@code ThreadContext} under the specified {@code key}, or {@code null} if there
     * is no value for that {@code key}.
     */
    private static Object getValue(Object key) {
        return resources.get().get(key);
    }

    /**
     * Returns the object for the specified <code>key</code> that is bound to
     * the current thread.
     *
     * @param key the key that identifies the value to return
     * @return the object keyed by <code>key</code> or <code>null</code> if
     * no value exists for the specified <code>key</code>
     */
    public static Object get(Object key) {
        if (log.isTraceEnabled()) {
            String msg = "get() - in thread [" + Thread.currentThread().getName() + "]";
            log.trace(msg);
        }

        Object value = getValue(key);
        if ((value != null) && log.isTraceEnabled()) {
            String msg = "Retrieved value of type [" + value.getClass().getName() + "] for key [" +
                    key + "] " + "bound to thread [" + Thread.currentThread().getName() + "]";
            log.trace(msg);
        }
        return value;
    }

    /**
     * Binds <tt>value</tt> for the given <code>key</code> to the current thread.
     * <p/>
     * <p>A <tt>null</tt> <tt>value</tt> has the same effect as if <tt>remove</tt> was called for the given
     * <tt>key</tt>, i.e.:
     * <p/>
     * <pre>
     * if ( value == null ) {
     *     remove( key );
     * }</pre>
     *
     * @param key   The key with which to identify the <code>value</code>.
     * @param value The value to bind to the thread.
     * @throws IllegalArgumentException if the <code>key</code> argument is <tt>null</tt>.
     */
    public static void put(Object key, Object value) {
        if (key == null) {
            throw new IllegalArgumentException("key cannot be null");
        }

        if (value == null) {
            remove(key);
            return;
        }

        resources.get().put(key, value);

        if (log.isTraceEnabled()) {
            String msg = "Bound value of type [" + value.getClass().getName() + "] for key [" +
                    key + "] to thread " + "[" + Thread.currentThread().getName() + "]";
            log.trace(msg);
        }
    }

    /**
     * Unbinds the value for the given <code>key</code> from the current
     * thread.
     *
     * @param key The key identifying the value bound to the current thread.
     * @return the object unbound or <tt>null</tt> if there was nothing bound
     * under the specified <tt>key</tt> name.
     */
    public static Object remove(Object key) {
        Object value = resources.get().remove(key);

        if ((value != null) && log.isTraceEnabled()) {
            String msg = "Removed value of type [" + value.getClass().getName() + "] for key [" +
                    key + "]" + "from thread [" + Thread.currentThread().getName() + "]";
            log.trace(msg);
        }

        return value;
    }

    /**
     * {@link ThreadLocal#remove Remove}s the underlying {@link ThreadLocal ThreadLocal} from the thread.
     * <p/>
     * This method is meant to be the final 'clean up' operation that is called at the end of thread execution to
     * prevent thread corruption in pooled thread environments.
     */
    public static void remove() {
        resources.remove();
    }

    /**
     * Convenience method that simplifies retrieval of the application's SecurityManager instance from the current
     * thread. If there is no SecurityManager bound to the thread (probably because framework code did not bind it
     * to the thread), this method returns <tt>null</tt>.
     * <p/>
     * It is merely a convenient wrapper for the following:
     * <p/>
     * <code>return (SecurityManager)get( SECURITY_MANAGER_KEY );</code>
     * <p/>
     * This method only returns the bound value if it exists - it does not remove it
     * from the thread.  To remove it, one must call {@link #unbindSecurityManager() unbindSecurityManager()} instead.
     *
     * @return the Subject object bound to the thread, or <tt>null</tt> if there isn't one bound.
     */
    public static WebSecurityManager getSecurityManager() {
        return (WebSecurityManager) get(SECURITY_MANAGER_KEY);
    }

    /**
     * Convenience method that simplifies binding the application's SecurityManager instance to the ThreadContext.
     * <p/>
     * <p>The method's existence is to help reduce casting in code and to simplify remembering of
     * ThreadContext key names.  The implementation is simple in that, if the SecurityManager is not <tt>null</tt>,
     * it binds it to the thread, i.e.:
     * <p/>
     * <pre>
     * if (securityManager != null) {
     *     put( SECURITY_MANAGER_KEY, securityManager);
     * }</pre>
     *
     * @param securityManager the application's SecurityManager instance to bind to the thread.  If the argument is
     *                        null, nothing will be done.
     */
    public static void bind(WebSecurityManager securityManager) {
        if (securityManager != null) {
            put(SECURITY_MANAGER_KEY, securityManager);
        }
    }

    /**
     * Convenience method that simplifies removal of the application's SecurityManager instance from the thread.
     * <p/>
     * The implementation just helps reduce casting and remembering of the ThreadContext key name, i.e it is
     * merely a conveient wrapper for the following:
     * <p/>
     * <code>return (SecurityManager)remove( SECURITY_MANAGER_KEY );</code>
     * <p/>
     * If you wish to just retrieve the object from the thread without removing it (so it can be retrieved later
     * during thread execution), use the {@link #getSecurityManager() getSecurityManager()} method instead.
     *
     * @return the application's SecurityManager instance previously bound to the thread, or <tt>null</tt> if there
     * was none bound.
     */
    public static WebSecurityManager unbindSecurityManager() {
        return (WebSecurityManager) remove(SECURITY_MANAGER_KEY);
    }

    /**
     * Convenience method that simplifies retrieval of a thread-bound Subject.  If there is no
     * Subject bound to the thread, this method returns <tt>null</tt>.  It is merely a convenient wrapper
     * for the following:
     * <p/>
     * <code>return (Subject)get( SUBJECT_KEY );</code>
     * <p/>
     * This method only returns the bound value if it exists - it does not remove it
     * from the thread.  To remove it, one must call {@link #unbindSubject() unbindSubject()} instead.
     *
     * @return the Subject object bound to the thread, or <tt>null</tt> if there isn't one bound.
     */
    public static WebSubject getSubject() {
        return (WebSubject) get(SUBJECT_KEY);
    }

    /**
     * Convenience method that simplifies binding a Subject to the ThreadContext.
     * <p/>
     * <p>The method's existence is to help reduce casting in your own code and to simplify remembering of
     * ThreadContext key names.  The implementation is simple in that, if the Subject is not <tt>null</tt>,
     * it binds it to the thread, i.e.:
     * <p/>
     * <pre>
     * if (subject != null) {
     *     put( SUBJECT_KEY, subject );
     * }</pre>
     *
     * @param subject the Subject object to bind to the thread.  If the argument is null, nothing will be done.
     */
    public static void bind(WebSubject subject) {
        if (subject != null) {
            put(SUBJECT_KEY, subject);
        }
    }

    /**
     * Convenience method that simplifies removal of a thread-local Subject from the thread.
     * <p/>
     * The implementation just helps reduce casting and remembering of the ThreadContext key name, i.e it is
     * merely a conveient wrapper for the following:
     * <p/>
     * <code>return (Subject)remove( SUBJECT_KEY );</code>
     * <p/>
     * If you wish to just retrieve the object from the thread without removing it (so it can be retrieved later during
     * thread execution), you should use the {@link #getSubject() getSubject()} method for that purpose.
     *
     * @return the Subject object previously bound to the thread, or <tt>null</tt> if there was none bound.
     */
    public static Subject unbindSubject() {
        return (Subject) remove(SUBJECT_KEY);
    }

    private static final class InheritableThreadLocalMap<T extends Map<Object, Object>> extends InheritableThreadLocal<Map<Object, Object>> {
        protected Map<Object, Object> initialValue() {
            return new HashMap<>();
        }

        /**
         * This implementation was added to address a
         * <a href="http://jsecurity.markmail.org/search/?q=#query:+page:1+mid:xqi2yxurwmrpqrvj+state:results">
         * user-reported issue</a>.
         *
         * @param parentValue the parent value, a HashMap as defined in the {@link #initialValue()} method.
         * @return the HashMap to be used by any parent-spawned child threads (a clone of the parent HashMap).
         */
        @SuppressWarnings({"unchecked"})
        protected Map<Object, Object> childValue(Map<Object, Object> parentValue) {
            if (parentValue != null) {
                return (Map<Object, Object>) ((HashMap<Object, Object>) parentValue).clone();
            } else {
                return null;
            }
        }
    }
}

