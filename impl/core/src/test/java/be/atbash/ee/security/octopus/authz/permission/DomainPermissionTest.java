/*
 * Copyright 2014-2020 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.authz.permission;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class DomainPermissionTest {

    @Test
    public void defaultConstructor() {
        DomainPermission p = new DomainPermission();

        // Verify domain
        assertThat(p.getDomain()).isEqualTo("domain");
        // Verify actions
        assertThat(p.getActions()).isNull();

        // Verify targets
        assertThat(p.getTargets()).isNull();

        // Verify parts
        List<Set<String>> parts = p.getParts();
        assertThat(parts).hasSize(1);

        assertThat(parts.get(0)).containsOnly("domain");
    }

    @Test
    public void actionsConstructorWithSingleAction() {
        // Actions constructor with a single action
        DomainPermission p = new DomainPermission("action1");

        // Verify domain
        assertThat(p.getDomain()).isEqualTo("domain");

        // Verify actions
        assertThat(p.getActions()).isNotNull();
        assertThat(p.getActions()).containsOnly("action1");

        // Verify targets
        assertThat(p.getTargets()).isNull();

        // Verify parts
        List<Set<String>> parts = p.getParts();
        assertThat(parts).hasSize(2);

        assertThat(parts.get(0)).containsOnly("domain");
        assertThat(parts.get(1)).containsOnly("action1");
    }

    @Test
    public void actionsConstructorWithMultipleActions() {

        // Actions constructor with three actions
        DomainPermission p = new DomainPermission("action1,action2,action3");

        // Verify domain
        assertThat(p.getDomain()).isEqualTo("domain");

        // Verify actions
        assertThat(p.getActions()).isNotNull();
        assertThat(p.getActions()).containsExactly("action1", "action2", "action3");

        // Verify targets
        assertThat(p.getTargets()).isNull();

        // Verify parts
        List<Set<String>> parts = p.getParts();
        assertThat(parts).hasSize(2);

        assertThat(parts.get(0)).containsOnly("domain");
        assertThat(parts.get(1)).containsExactly("action1", "action2", "action3");

    }

    @Test
    public void actionsTargetsConstructorWithSingleActionAndTarget() {
        // Actions constructor with three actions
        DomainPermission p = new DomainPermission("action1", "target1");

        // Verify domain
        assertThat(p.getDomain()).isEqualTo("domain");

        // Verify actions
        assertThat(p.getActions()).isNotNull();
        assertThat(p.getActions()).containsOnly("action1");

        // Verify targets
        assertThat(p.getTargets()).isNotNull();
        assertThat(p.getTargets()).containsOnly("target1");

        // Verify parts
        List<Set<String>> parts = p.getParts();
        assertThat(parts).hasSize(3);

        assertThat(parts.get(0)).containsOnly("domain");
        assertThat(parts.get(1)).containsOnly("action1");
        assertThat(parts.get(2)).containsOnly("target1");
    }

    @Test
    public void actionsTargetsConstructorWithMultipleActionsAndTargets() {
        // Actions constructor with three actions
        DomainPermission p = new DomainPermission("action1,action2,action3", "target1,target2,target3");

        // Verify domain
        assertThat(p.getDomain()).isEqualTo("domain");

        // Verify actions
        assertThat(p.getActions()).isNotNull();
        assertThat(p.getActions()).containsExactly("action1", "action2", "action3");

        // Verify targets
        assertThat(p.getTargets()).isNotNull();
        assertThat(p.getTargets()).containsExactly("target1", "target2", "target3");

        // Verify parts
        List<Set<String>> parts = p.getParts();
        assertThat(parts).hasSize(3);

        assertThat(parts.get(0)).containsOnly("domain");
        assertThat(parts.get(1)).containsExactly("action1", "action2", "action3");
        assertThat(parts.get(2)).containsExactly("target1", "target2", "target3");

    }

}