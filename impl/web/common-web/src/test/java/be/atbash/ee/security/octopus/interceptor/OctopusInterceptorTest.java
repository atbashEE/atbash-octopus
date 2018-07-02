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
package be.atbash.ee.security.octopus.interceptor;

import be.atbash.ee.security.octopus.authc.AuthenticationInfoProviderHandler;
import be.atbash.ee.security.octopus.authc.SimpleAuthenticationInfo;
import be.atbash.ee.security.octopus.authz.AuthorizationException;
import be.atbash.ee.security.octopus.authz.AuthorizationInfoProviderHandler;
import be.atbash.ee.security.octopus.authz.SimpleAuthorizationInfo;
import be.atbash.ee.security.octopus.authz.checks.*;
import be.atbash.ee.security.octopus.authz.permission.NamedDomainPermission;
import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.ee.security.octopus.authz.permission.PermissionResolver;
import be.atbash.ee.security.octopus.authz.permission.WildcardPermission;
import be.atbash.ee.security.octopus.authz.permission.role.RolePermission;
import be.atbash.ee.security.octopus.authz.violation.BasicAuthorizationViolation;
import be.atbash.ee.security.octopus.authz.violation.SecurityAuthorizationViolationException;
import be.atbash.ee.security.octopus.authz.violation.SecurityViolationInfoProducer;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.config.names.VoterNameFactory;
import be.atbash.ee.security.octopus.context.ThreadContext;
import be.atbash.ee.security.octopus.context.internal.OctopusInvocationContext;
import be.atbash.ee.security.octopus.interceptor.testclasses.TestCustomVoter;
import be.atbash.ee.security.octopus.interceptor.testclasses.TestPermissionCheck;
import be.atbash.ee.security.octopus.interceptor.testclasses.TestRoleCheck;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.systemaccount.SystemAccountPrincipal;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.ValidatedAuthenticationToken;
import be.atbash.ee.security.octopus.util.onlyduring.TemporaryAuthorizationContextManager;
import be.atbash.util.BeanManagerFake;
import be.atbash.util.TestReflectionUtils;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.mockito.ArgumentMatchers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import javax.interceptor.InvocationContext;
import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

/**
 *
 */
@Ignore
public class OctopusInterceptorTest {
    protected static final String PERMISSION1 = "PERMISSION1";
    protected static final String PERMISSION2 = "PERMISSION2";
    protected static final String PERMISSION1_WILDCARD = "permission:1:*";
    protected static final String PERMISSION2_WILDCARD = "permission:2:*";
    protected static final Boolean NOT_AUTHENTICATED = Boolean.FALSE;
    protected static final Boolean AUTHENTICATED = Boolean.TRUE;
    protected static final Boolean NO_CUSTOM_ACCESS = Boolean.FALSE;
    protected static final Boolean CUSTOM_ACCESS = Boolean.TRUE;
    protected static final String ACCOUNT1 = "account1";
    protected static final String NAMED_OCTOPUS = "named:octopus:*";
    protected static final String OCTOPUS1 = "octopus1:*:*";
    protected static final String OCTOPUS2 = "octopus2:*:*";
    protected static final String ROLE1 = "role1";
    protected static final String ROLE2 = "role2";

    protected SecurityCheckRequiresPermissions securityCheckRequiresPermissions;
    protected SecurityCheckRequiresRoles securityCheckRequiresRoles;

    protected static final String AUTHORIZATION_PERMISSION = "Authorization:*:*";

    @Mock
    protected OctopusCoreConfiguration octopusConfigMock;

    //@Mock
    //private TwoStepConfig twoStepConfigConfigMock;

    @Mock
    private SecurityViolationInfoProducer infoProducerMock;

    @Mock
    protected Subject subjectMock;

    @Mock
    protected AuthenticationInfoProviderHandler authenticationInfoProviderHandlerMock;

    @Mock
    protected AuthorizationInfoProviderHandler authorizationInfoProviderHandlerMock;

    @Mock
    protected PermissionResolver permissionResolverMock;

    @InjectMocks
    protected OctopusInterceptor octopusInterceptor;

    protected VoterNameFactory voterNameFactory;

    protected BeanManagerFake beanManagerFake;

    protected boolean authenticated;
    protected String permission;
    protected boolean customAccess;
    protected String systemAccount;
    protected String role;

    public OctopusInterceptorTest(boolean authenticated, String permission, boolean customAccess, String systemAccount, String role) {
        this.authenticated = authenticated;
        this.permission = permission;
        this.customAccess = customAccess;
        this.systemAccount = systemAccount;
        this.role = role;
    }

    @Before
    public void setup() throws IllegalAccessException {
        CallFeedbackCollector.reset();
        initMocks(this);

        ThreadContext.bind(subjectMock);
        if (authenticated) {
            if (systemAccount != null) {
                SystemAccountPrincipal systemAccountPrincipal = new SystemAccountPrincipal(systemAccount);
                when(subjectMock.getPrincipal()).thenReturn(systemAccountPrincipal);
            } else {

                UserPrincipal userPrincipal = new UserPrincipal("id", "atbash", "Atbash");
                when(subjectMock.getPrincipal()).thenReturn(userPrincipal);

            }
            when(subjectMock.isAuthenticated()).thenReturn(true);
        } else {
            when(subjectMock.isAuthenticated()).thenReturn(false);
        }

        // Define logic at subject level to see if subject has the required permission
        final NamedDomainPermission namedPermission = getNamedDomainPermission(permission);
        final RolePermission namedRole = getNamedApplicationRole(role);

        doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) {
                Object parameter = invocationOnMock.getArguments()[0];
                if (parameter instanceof Permission) {
                    Permission permission = (Permission) parameter;
                    if (namedPermission == null && namedRole == null) {
                        throw new AuthorizationException();
                    }
                    if (namedPermission != null && !namedPermission.implies(permission)) {
                        throw new AuthorizationException();
                    }
                    if (namedRole != null && !namedRole.implies(permission)) {
                        throw new AuthorizationException();
                    }
                    return null;
                }
                throw new IllegalArgumentException();
            }
        }).when(subjectMock).checkPermission((Permission) ArgumentMatchers.any());

        doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) {
                Object parameter = invocationOnMock.getArguments()[0];
                if (parameter instanceof Permission) {
                    Permission permission = (Permission) parameter;
                    if (namedPermission == null && namedRole == null) {
                        return false;
                    }
                    if (namedPermission != null && !namedPermission.implies(permission)) {
                        return false;
                    }
                    return namedRole == null || namedRole.implies(permission);

                }
                throw new IllegalArgumentException();
            }
        }).when(subjectMock).isPermitted((Permission) ArgumentMatchers.any());

        doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) {
                Object parameter = invocationOnMock.getArguments()[0];
                if (parameter instanceof String) {
                    String permissionParameter = (String) parameter;
                    if (!permissionParameter.equals(permission)) {
                        throw new AuthorizationException();
                    } else {
                        return null;
                    }
                }
                if (parameter instanceof String[]) {
                    // as we don't support it in these tests
                    throw new AuthorizationException();
                }
                throw new IllegalArgumentException();
            }
        }).when(subjectMock).checkPermissions((String[]) ArgumentMatchers.any());

        doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) {
                Object parameter = invocationOnMock.getArguments()[0];
                if (parameter instanceof String) {
                    String permissionString = (String) parameter;
                    if (permissionString.contains(":")) {
                        return new WildcardPermission(permissionString);
                    }
                    System.out.println(parameter);
                    throw new IllegalArgumentException();
                }
                throw new IllegalArgumentException();
            }
        }).when(permissionResolverMock).resolvePermission(ArgumentMatchers.anyString());

        // Define the Named permission check class
        when(octopusConfigMock.getNamedPermissionCheckClass()).thenAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) {
                return TestPermissionCheck.class;
            }
        });

        // Define the Named permission check class
        when(octopusConfigMock.getNamedRoleCheckClass()).thenAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) {
                return TestRoleCheck.class;
            }
        });

        when(octopusConfigMock.getPermissionVoterSuffix()).thenReturn("PermissionVoter");
        when(octopusConfigMock.getRoleVoterSuffix()).thenReturn("RoleVoter");

        // startup mock system for manual/programmatic CDI retrieval
        beanManagerFake = new BeanManagerFake();

        beanManagerFake.registerBean(octopusConfigMock, OctopusCoreConfiguration.class);

        // SecurityViolationInfoProducer mock instance assigned to CDI and playback
        beanManagerFake.registerBean(infoProducerMock, SecurityViolationInfoProducer.class);
        when(infoProducerMock.getViolationInfo(ArgumentMatchers.any(AccessDecisionVoterContext.class), ArgumentMatchers.any(NamedDomainPermission.class))).thenReturn("Violation Info");
        when(infoProducerMock.getViolationInfo(ArgumentMatchers.any(AccessDecisionVoterContext.class))).thenReturn("Violation Info");
        when(infoProducerMock.defineViolation(ArgumentMatchers.any(OctopusInvocationContext.class), ArgumentMatchers.any(Permission.class))).thenReturn(new BasicAuthorizationViolation("X", "Y"));

        // The custom voter bound to CDI
        TestCustomVoter customVoter = new TestCustomVoter();
        customVoter.setCustomAccess(customAccess);
        beanManagerFake.registerBean(customVoter, TestCustomVoter.class);

        voterNameFactory = new VoterNameFactory();

        SecurityCheckOnlyDuringAuthorization securityCheckOnlyDuringAuthorization = new SecurityCheckOnlyDuringAuthorization();
        TestReflectionUtils.injectDependencies(securityCheckOnlyDuringAuthorization, infoProducerMock);

        beanManagerFake.registerBean(securityCheckOnlyDuringAuthorization, SecurityCheck.class);

        SecurityCheckRequiresUser securityCheckRequiresUser = new SecurityCheckRequiresUser();
        TestReflectionUtils.injectDependencies(securityCheckRequiresUser, infoProducerMock);

        beanManagerFake.registerBean(securityCheckRequiresUser, SecurityCheck.class);

        SecurityCheckOnlyDuringAuthentication securityCheckOnlyDuringAuthentication = new SecurityCheckOnlyDuringAuthentication();
        TestReflectionUtils.injectDependencies(securityCheckOnlyDuringAuthentication, infoProducerMock);

        beanManagerFake.registerBean(securityCheckOnlyDuringAuthentication, SecurityCheck.class);

        SecurityCheckOnlyDuringAuthenticationEvent securityCheckOnlyDuringAuthenticationEvent = new SecurityCheckOnlyDuringAuthenticationEvent();
        TestReflectionUtils.injectDependencies(securityCheckOnlyDuringAuthenticationEvent, infoProducerMock);

        beanManagerFake.registerBean(securityCheckOnlyDuringAuthenticationEvent, SecurityCheck.class);

        SecurityCheckNamedPermissionCheck securityCheckNamedPermissionCheck = new SecurityCheckNamedPermissionCheck();
        TestReflectionUtils.injectDependencies(securityCheckNamedPermissionCheck, infoProducerMock, octopusConfigMock, voterNameFactory);

        beanManagerFake.registerBean(securityCheckNamedPermissionCheck, SecurityCheck.class);

        SecurityCheckNamedRoleCheck securityCheckNamedRoleCheck = new SecurityCheckNamedRoleCheck();
        TestReflectionUtils.injectDependencies(securityCheckNamedRoleCheck, infoProducerMock, octopusConfigMock, voterNameFactory);

        beanManagerFake.registerBean(securityCheckNamedRoleCheck, SecurityCheck.class);

        SecurityCheckCustomVoterCheck securityCheckCustomVoterCheck = new SecurityCheckCustomVoterCheck();
        TestReflectionUtils.injectDependencies(securityCheckCustomVoterCheck, infoProducerMock);
        beanManagerFake.registerBean(securityCheckCustomVoterCheck, SecurityCheck.class);

        SecurityCheckSystemAccountCheck securityCheckSystemAccountCheck = new SecurityCheckSystemAccountCheck();
        TestReflectionUtils.injectDependencies(securityCheckSystemAccountCheck, infoProducerMock);

        beanManagerFake.registerBean(securityCheckSystemAccountCheck, SecurityCheck.class);

        securityCheckRequiresPermissions = new SecurityCheckRequiresPermissions();
        TestReflectionUtils.injectDependencies(securityCheckRequiresPermissions, infoProducerMock);
        securityCheckRequiresPermissions.init();

        beanManagerFake.registerBean(securityCheckRequiresPermissions, SecurityCheck.class);

        securityCheckRequiresRoles = new SecurityCheckRequiresRoles();
        TestReflectionUtils.injectDependencies(securityCheckRequiresRoles, infoProducerMock);

        beanManagerFake.registerBean(securityCheckRequiresRoles, SecurityCheck.class);
    }

    @After
    public void teardown() {
        beanManagerFake.deregistration();

        assertThat(TemporaryAuthorizationContextManager.isInAuthorization()).isFalse();
    }

    protected void finishCDISetup() throws IllegalAccessException {
        beanManagerFake.endRegistration();

        AnnotationAuthorizationChecker authorizationChecker = new AnnotationAuthorizationChecker();

        AnnotationCheckFactory checkFactory = new AnnotationCheckFactory();
        checkFactory.init();

        SecurityCheckDataFactory securityCheckDataFactory = new SecurityCheckDataFactory();
        TestReflectionUtils.injectDependencies(securityCheckDataFactory, octopusConfigMock);

        TestReflectionUtils.injectDependencies(authorizationChecker, checkFactory, securityCheckDataFactory);

        TestReflectionUtils.injectDependencies(octopusInterceptor, authorizationChecker);
    }

    protected NamedDomainPermission getNamedDomainPermission(String permissionName) {
        NamedDomainPermission result = null;
        if (permissionName != null) {

            result = new NamedDomainPermission(permissionName, permissionName.toLowerCase(Locale.ENGLISH), "*", "*");
        }
        return result;
    }

    protected RolePermission getNamedApplicationRole(String roleName) {
        RolePermission result = null;
        if (roleName != null) {

            result = new RolePermission(roleName);
        }
        return result;
    }

    protected Answer<Object> callInterceptorSimulatingAuthentication(final InvocationContext context) {
        return new Answer<Object>() {

            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {

                try {
                    octopusInterceptor.interceptForSecurity(context);
                } catch (Exception e) {
                    if (e instanceof SecurityAuthorizationViolationException) {
                        throw e;
                    }
                    throw new RuntimeException(e);
                }
                UserPrincipal userPrincipal = new UserPrincipal("id", "atbash", "Atbash");
                return new SimpleAuthenticationInfo(userPrincipal, "Credentials");

            }

        };
    }

    protected Answer<Object> callInterceptorSimulatingAuthorization(final InvocationContext context) {
        return new Answer<Object>() {

            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {

                try {
                    octopusInterceptor.interceptForSecurity(context);
                } catch (Exception e) {
                    if (e instanceof SecurityAuthorizationViolationException) {
                        throw e;
                    }
                    throw new RuntimeException(e);
                }
                SimpleAuthorizationInfo result = new SimpleAuthorizationInfo();
                result.addStringPermission(AUTHORIZATION_PERMISSION);
                return result;

            }

        };
    }

    static class SpecialValidatedToken implements AuthenticationToken, ValidatedAuthenticationToken {

        @Override
        public Object getPrincipal() {
            return null;
        }

        @Override
        public Object getCredentials() {
            return null;
        }
    }
}
