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
package be.atbash.ee.security.octopus.filter.authz;

import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.ee.security.octopus.authz.permission.role.NamedRole;
import be.atbash.ee.security.octopus.authz.permission.role.RolePermission;
import be.atbash.ee.security.octopus.authz.permission.typesafe.RoleLookup;
import be.atbash.ee.security.octopus.context.ThreadContext;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.util.BeanManagerFake;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class NamedRoleFilterTest {

    private BeanManagerFake beanManagerFake;

    @Mock
    private WebSubject subjectMock;

    @Mock
    private RoleLookup<? extends NamedRole> roleLookupMock;

    private NamedRoleFilter filter;

    @Captor
    private ArgumentCaptor<Permission> permissionArgumentCaptor;

    @Before
    public void setup() {
        beanManagerFake = new BeanManagerFake();

        filter = new NamedRoleFilter();

        ThreadContext.bind(subjectMock);
    }

    @After
    public void cleanup() {
        beanManagerFake.deregistration();
    }

    @Test
    public void isAccessAllowed_noMapping_allowed() throws Exception {
        beanManagerFake.endRegistration();
        filter.initInstance();

        when(subjectMock.isPermitted(any(Permission.class))).thenReturn(true);
        boolean allowed = filter.isAccessAllowed(null, null, new String[]{"role1"});
        assertThat(allowed).isTrue();

        verify(subjectMock).isPermitted(permissionArgumentCaptor.capture());
        assertThat(permissionArgumentCaptor.getValue()).isInstanceOf(RolePermission.class);

        Permission permission = permissionArgumentCaptor.getValue();
        assertThat(permission.toString()).isEqualTo(">role1<");

    }

    @Test
    public void isAccessAllowed_noMapping_notAllowed() throws Exception {
        beanManagerFake.endRegistration();
        filter.initInstance();

        when(subjectMock.isPermitted(any(Permission.class))).thenReturn(false);
        boolean allowed = filter.isAccessAllowed(null, null, new String[]{"role3"});
        assertThat(allowed).isFalse();

        verify(subjectMock).isPermitted(permissionArgumentCaptor.capture());
        assertThat(permissionArgumentCaptor.getValue()).isInstanceOf(RolePermission.class);

        Permission permission = permissionArgumentCaptor.getValue();
        assertThat(permission.toString()).isEqualTo(">role3<");

    }

    @Test
    public void isAccessAllowed_noMapping_multiple_allowed() throws Exception {
        beanManagerFake.endRegistration();
        filter.initInstance();

        when(subjectMock.isPermitted(any(Permission.class))).thenReturn(true);
        boolean allowed = filter.isAccessAllowed(null, null, new String[]{"role1", "role2"});
        assertThat(allowed).isTrue();

        verify(subjectMock, times(2)).isPermitted(permissionArgumentCaptor.capture());

        List<Permission> allValues = permissionArgumentCaptor.getAllValues();
        assertThat(allValues).hasSize(2);
        Permission permission = allValues.get(0);
        assertThat(permission.toString()).isEqualTo(">role1<");

        permission = allValues.get(1);
        assertThat(permission.toString()).isEqualTo(">role2<");

    }

    @Test
    public void isAccessAllowed_noMapping_multiple_oneNotAllowed() throws Exception {
        beanManagerFake.endRegistration();
        filter.initInstance();

        when(subjectMock.isPermitted(any(Permission.class))).thenAnswer(
                new Answer<Object>() {
                    @Override
                    public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                        Permission permission = (Permission) invocationOnMock.getArguments()[0];
                        return ">role1<".equals(permission.toString());
                    }
                }
        );
        boolean allowed = filter.isAccessAllowed(null, null, new String[]{"role1", "role2"});
        assertThat(allowed).isFalse();

        verify(subjectMock, times(2)).isPermitted(permissionArgumentCaptor.capture());

        List<Permission> allValues = permissionArgumentCaptor.getAllValues();
        assertThat(allValues).hasSize(2);
        Permission permission = allValues.get(0);
        assertThat(permission.toString()).isEqualTo(">role1<");

        permission = allValues.get(1);
        assertThat(permission.toString()).isEqualTo(">role2<");

    }

    @Test
    public void isAccessAllowed_mapping_allowed() throws Exception {
        beanManagerFake.registerBean(roleLookupMock, RoleLookup.class);
        beanManagerFake.endRegistration();
        filter.initInstance();

        when(roleLookupMock.getRole("role1")).thenReturn(new RolePermission("mappedRole1"));

        when(subjectMock.isPermitted(any(Permission.class))).thenReturn(true);
        boolean allowed = filter.isAccessAllowed(null, null, new String[]{"role1"});
        assertThat(allowed).isTrue();

        verify(subjectMock).isPermitted(permissionArgumentCaptor.capture());
        assertThat(permissionArgumentCaptor.getValue()).isInstanceOf(RolePermission.class);

        Permission permission = permissionArgumentCaptor.getValue();
        assertThat(permission.toString()).isEqualTo(">mappedRole1<");

    }

    @Test
    public void isAccessAllowed_mapping_notAllowed() throws Exception {
        beanManagerFake.registerBean(roleLookupMock, RoleLookup.class);
        beanManagerFake.endRegistration();
        filter.initInstance();

        when(roleLookupMock.getRole("role3")).thenReturn(new RolePermission("mappedRole3"));

        when(subjectMock.isPermitted(any(Permission.class))).thenReturn(false);
        boolean allowed = filter.isAccessAllowed(null, null, new String[]{"role3"});
        assertThat(allowed).isFalse();

        verify(subjectMock).isPermitted(permissionArgumentCaptor.capture());
        assertThat(permissionArgumentCaptor.getValue()).isInstanceOf(RolePermission.class);

        Permission permission = permissionArgumentCaptor.getValue();
        assertThat(permission.toString()).isEqualTo(">mappedRole3<");

    }

    @Test
    public void isAccessAllowed_mapping_multiple_allowed() throws Exception {
        beanManagerFake.registerBean(roleLookupMock, RoleLookup.class);
        beanManagerFake.endRegistration();
        filter.initInstance();

        when(roleLookupMock.getRole("role1")).thenReturn(new RolePermission("mappedRole1"));
        when(roleLookupMock.getRole("role2")).thenReturn(new RolePermission("mappedRole2"));

        when(subjectMock.isPermitted(any(Permission.class))).thenReturn(true);
        boolean allowed = filter.isAccessAllowed(null, null, new String[]{"role1", "role2"});
        assertThat(allowed).isTrue();

        verify(subjectMock, times(2)).isPermitted(permissionArgumentCaptor.capture());

        List<Permission> allValues = permissionArgumentCaptor.getAllValues();
        assertThat(allValues).hasSize(2);
        Permission permission = allValues.get(0);
        assertThat(permission.toString()).isEqualTo(">mappedRole1<");

        permission = allValues.get(1);
        assertThat(permission.toString()).isEqualTo(">mappedRole2<");

    }

    @Test
    public void isAccessAllowed_mapping_multiple_oneNotAllowed() throws Exception {
        beanManagerFake.registerBean(roleLookupMock, RoleLookup.class);
        beanManagerFake.endRegistration();
        filter.initInstance();

        when(roleLookupMock.getRole("role1")).thenReturn(new RolePermission("mappedRole1"));
        when(roleLookupMock.getRole("role3")).thenReturn(new RolePermission("mappedRole3"));

        when(subjectMock.isPermitted(any(Permission.class))).thenAnswer(
                new Answer<Object>() {
                    @Override
                    public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                        Permission permission = (Permission) invocationOnMock.getArguments()[0];
                        return ">mappedRole1<".equals(permission.toString());
                    }
                }
        );

        boolean allowed = filter.isAccessAllowed(null, null, new String[]{"role1", "role3"});
        assertThat(allowed).isFalse();

        verify(subjectMock, times(2)).isPermitted(permissionArgumentCaptor.capture());

        List<Permission> allValues = permissionArgumentCaptor.getAllValues();
        assertThat(allValues).hasSize(2);
        Permission permission = allValues.get(0);
        assertThat(permission.toString()).isEqualTo(">mappedRole1<");

        permission = allValues.get(1);
        assertThat(permission.toString()).isEqualTo(">mappedRole3<");

    }
}