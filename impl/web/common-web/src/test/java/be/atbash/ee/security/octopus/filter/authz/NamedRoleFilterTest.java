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
package be.atbash.ee.security.octopus.filter.authz;

import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.ee.security.octopus.authz.permission.role.NamedRole;
import be.atbash.ee.security.octopus.authz.permission.role.RolePermission;
import be.atbash.ee.security.octopus.authz.permission.typesafe.RoleLookup;
import be.atbash.ee.security.octopus.context.ThreadContext;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.util.BeanManagerFake;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.stubbing.Answer;

import javax.servlet.ServletRequest;
import java.util.List;

import static be.atbash.ee.security.octopus.OctopusConstants.OCTOPUS_VIOLATION_MESSAGE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 *
 */
@ExtendWith(MockitoExtension.class)
public class NamedRoleFilterTest {

    private BeanManagerFake beanManagerFake;

    @Mock
    private WebSubject subjectMock;

    @Mock
    private RoleLookup<? extends NamedRole> roleLookupMock;

    @Mock
    private ServletRequest servletRequestMock;

    private NamedRoleFilter filter;

    @Captor
    private ArgumentCaptor<Permission> permissionArgumentCaptor;

    @Captor
    private ArgumentCaptor<String> stringArgumentCaptor;

    @Captor
    private ArgumentCaptor<String> attributeNameCaptor;

    @BeforeEach
    public void setup() {
        beanManagerFake = new BeanManagerFake();

        filter = new NamedRoleFilter();

        ThreadContext.bind(subjectMock);
    }

    @AfterEach
    public void cleanup() {
        beanManagerFake.deregistration();
    }

    @Test
    public void isAccessAllowed_noMapping_allowed() throws Exception {
        beanManagerFake.endRegistration();
        filter.initInstance();

        when(subjectMock.isPermitted(any(Permission.class))).thenReturn(true);
        when(servletRequestMock.getAttribute("octopus.pathConfig")).thenReturn(new String[]{"role1"});

        boolean allowed = filter.isAccessAllowed(servletRequestMock, null);
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
        when(servletRequestMock.getAttribute("octopus.pathConfig")).thenReturn(new String[]{"role3"});

        boolean allowed = filter.isAccessAllowed(servletRequestMock, null);
        assertThat(allowed).isFalse();

        verify(subjectMock).isPermitted(permissionArgumentCaptor.capture());
        assertThat(permissionArgumentCaptor.getValue()).isInstanceOf(RolePermission.class);

        Permission permission = permissionArgumentCaptor.getValue();
        assertThat(permission.toString()).isEqualTo(">role3<");

        verify(servletRequestMock).setAttribute(attributeNameCaptor.capture(), stringArgumentCaptor.capture());

        assertThat(attributeNameCaptor.getValue()).isEqualTo(OCTOPUS_VIOLATION_MESSAGE);
        assertThat(stringArgumentCaptor.getValue()).isEqualTo("Violation of Role role3");

    }

    @Test
    public void isAccessAllowed_noMapping_multiple_allowed() throws Exception {
        beanManagerFake.endRegistration();
        filter.initInstance();

        when(subjectMock.isPermitted(any(Permission.class))).thenReturn(true);
        when(servletRequestMock.getAttribute("octopus.pathConfig")).thenReturn(new String[]{"role1", "role2"});

        boolean allowed = filter.isAccessAllowed(servletRequestMock, null);
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
        when(servletRequestMock.getAttribute("octopus.pathConfig")).thenReturn(new String[]{"role1", "role2"});

        boolean allowed = filter.isAccessAllowed(servletRequestMock, null);
        assertThat(allowed).isFalse();

        verify(subjectMock, times(2)).isPermitted(permissionArgumentCaptor.capture());

        List<Permission> allValues = permissionArgumentCaptor.getAllValues();
        assertThat(allValues).hasSize(2);
        Permission permission = allValues.get(0);
        assertThat(permission.toString()).isEqualTo(">role1<");

        permission = allValues.get(1);
        assertThat(permission.toString()).isEqualTo(">role2<");

        verify(servletRequestMock).setAttribute(attributeNameCaptor.capture(), stringArgumentCaptor.capture());

        assertThat(attributeNameCaptor.getValue()).isEqualTo(OCTOPUS_VIOLATION_MESSAGE);
        assertThat(stringArgumentCaptor.getValue()).isEqualTo("Violation of Role role2");

    }

    @Test
    public void isAccessAllowed_mapping_allowed() throws Exception {
        beanManagerFake.registerBean(roleLookupMock, RoleLookup.class);
        beanManagerFake.endRegistration();
        filter.initInstance();

        when(roleLookupMock.getRole("role1")).thenReturn(new RolePermission("mappedRole1"));

        when(subjectMock.isPermitted(any(Permission.class))).thenReturn(true);
        when(servletRequestMock.getAttribute("octopus.pathConfig")).thenReturn(new String[]{"role1"});

        boolean allowed = filter.isAccessAllowed(servletRequestMock, null);
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
        when(servletRequestMock.getAttribute("octopus.pathConfig")).thenReturn(new String[]{"role3"});

        boolean allowed = filter.isAccessAllowed(servletRequestMock, null);
        assertThat(allowed).isFalse();

        verify(subjectMock).isPermitted(permissionArgumentCaptor.capture());
        assertThat(permissionArgumentCaptor.getValue()).isInstanceOf(RolePermission.class);

        Permission permission = permissionArgumentCaptor.getValue();
        assertThat(permission.toString()).isEqualTo(">mappedRole3<");

        verify(servletRequestMock).setAttribute(attributeNameCaptor.capture(), stringArgumentCaptor.capture());

        assertThat(attributeNameCaptor.getValue()).isEqualTo(OCTOPUS_VIOLATION_MESSAGE);
        assertThat(stringArgumentCaptor.getValue()).isEqualTo("Violation of Role role3");

    }

    @Test
    public void isAccessAllowed_mapping_multiple_allowed() throws Exception {
        beanManagerFake.registerBean(roleLookupMock, RoleLookup.class);
        beanManagerFake.endRegistration();
        filter.initInstance();

        when(roleLookupMock.getRole("role1")).thenReturn(new RolePermission("mappedRole1"));
        when(roleLookupMock.getRole("role2")).thenReturn(new RolePermission("mappedRole2"));

        when(subjectMock.isPermitted(any(Permission.class))).thenReturn(true);
        when(servletRequestMock.getAttribute("octopus.pathConfig")).thenReturn(new String[]{"role1", "role2"});

        boolean allowed = filter.isAccessAllowed(servletRequestMock, null);
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

        when(servletRequestMock.getAttribute("octopus.pathConfig")).thenReturn(new String[]{"role1", "role3"});

        boolean allowed = filter.isAccessAllowed(servletRequestMock, null);
        assertThat(allowed).isFalse();

        verify(subjectMock, times(2)).isPermitted(permissionArgumentCaptor.capture());

        List<Permission> allValues = permissionArgumentCaptor.getAllValues();
        assertThat(allValues).hasSize(2);
        Permission permission = allValues.get(0);
        assertThat(permission.toString()).isEqualTo(">mappedRole1<");

        permission = allValues.get(1);
        assertThat(permission.toString()).isEqualTo(">mappedRole3<");

        verify(servletRequestMock).setAttribute(attributeNameCaptor.capture(), stringArgumentCaptor.capture());

        assertThat(attributeNameCaptor.getValue()).isEqualTo(OCTOPUS_VIOLATION_MESSAGE);
        assertThat(stringArgumentCaptor.getValue()).isEqualTo("Violation of Role role3");

    }
}