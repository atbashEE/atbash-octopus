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
package be.atbash.ee.security.octopus.javafx.authc;

import be.atbash.ee.security.octopus.token.AuthenticationToken;

public class UsernamePasswordToken implements AuthenticationToken {

    /**
     * The username
     */
    private String username;

    /**
     * The password, in char[] format
     */
    private char[] password;

    /**
     * Constructs a new UsernamePasswordToken encapsulating the username and password submitted
     * during an authentication attempt, with a <tt>null</tt> {@link #getHost() host} and
     * a <tt>rememberMe</tt> default of <tt>false</tt>
     * <p/>
     * <p>This is a convience constructor and maintains the password internally via a character
     * array, i.e. <tt>password.toCharArray();</tt>.  Note that storing a password as a String
     * in your code could have possible security implications as noted in the class JavaDoc.</p>
     *
     * @param username the username submitted for authentication
     * @param password the password string submitted for authentication
     */
    public UsernamePasswordToken(final String username, final String password) {
        this(username, password != null ? password.toCharArray() : null);
    }

    /**
     * Constructs a new UsernamePasswordToken encapsulating the username and password submitted, if the user
     * wishes their identity to be remembered across sessions, and the inetAddress from where the attempt is ocurring.
     *
     * @param username the username submitted for authentication
     * @param password the password character array submitted for authentication
     */
    public UsernamePasswordToken(String username, char[] password) {

        this.username = username;
        this.password = password;
    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    /**
     * Returns the username submitted during an authentication attempt.
     *
     * @return the username submitted during an authentication attempt.
     */
    public String getUsername() {
        return username;
    }

    /**
     * Returns the password submitted during an authentication attempt as a character array.
     *
     * @return the password submitted during an authentication attempt as a character array.
     */
    public char[] getPassword() {
        return password;
    }

    /**
     * Simply returns {@link #getUsername() getUsername()}.
     *
     * @return the {@link #getUsername() username}.
     */
    public Object getPrincipal() {
        return getUsername();
    }

    /**
     * Returns the {@link #getPassword() password} char array.
     *
     * @return the {@link #getPassword() password} char array.
     */
    public Object getCredentials() {
        return getPassword();
    }

    /**
     * Clears out (nulls) the username, password, rememberMe, and inetAddress.  The password bytes are explicitly set to
     * <tt>0x00</tt> before nulling to eliminate the possibility of memory access at a later time.
     */
    public void clear() {
        username = null;

        if (password != null) {
            for (int i = 0; i < password.length; i++) {
                password[i] = 0x00;
            }
            password = null;
        }

    }

    /**
     * Returns the String representation.  It does not include the password in the resulting
     * string for security reasons to prevent accidentially printing out a password
     * that might be widely viewable).
     *
     * @return the String representation of the <tt>UsernamePasswordToken</tt>, omitting
     * the password.
     */
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getName());
        sb.append(" - ");
        sb.append(username);
        return sb.toString();
    }

}
