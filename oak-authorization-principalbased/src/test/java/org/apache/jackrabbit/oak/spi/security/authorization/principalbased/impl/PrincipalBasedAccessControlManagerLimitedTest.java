/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.jackrabbit.oak.spi.security.authorization.principalbased.impl;

import com.google.common.collect.ImmutableSet;
import org.apache.jackrabbit.api.security.JackrabbitAccessControlList;
import org.apache.jackrabbit.api.security.JackrabbitAccessControlManager;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.oak.api.Root;
import org.apache.jackrabbit.oak.commons.PathUtils;
import org.apache.jackrabbit.oak.spi.security.authorization.accesscontrol.ImmutableACL;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeBits;
import org.apache.jackrabbit.oak.spi.security.privilege.PrivilegeConstants;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.junit.Before;
import org.junit.Test;

import javax.jcr.AccessDeniedException;
import javax.jcr.RepositoryException;
import javax.jcr.SimpleCredentials;
import javax.jcr.security.AccessControlPolicy;
import java.security.Principal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Tests for PrincipalBasedAccessControlManager where the editing session (based on a regular user with default
 * permission evaluation) lacks permissions to read/modify access control on the target system-principal.
 */
public class PrincipalBasedAccessControlManagerLimitedTest extends AbstractPrincipalBasedTest implements PrivilegeConstants {

    private Principal systemPrincipal;
    private String systemPrincipalPath;
    private Root testRoot;
    private JackrabbitAccessControlManager testAcMgr;

    @Before
    public void before() throws Exception {
        super.before();

        User systemUser = getTestSystemUser();
        systemPrincipalPath = systemUser.getPath();
        systemPrincipal = getTestSystemUser().getPrincipal();

        User testUser = getTestUser();
        setupContentTrees(TEST_OAK_PATH);

        // grant test-user full read access (but not read-access control!)
        addDefaultEntry(PathUtils.ROOT_PATH, testUser.getPrincipal(), JCR_READ);

        // trigger creation of principal policy with testPrincipal with 2 random entries
        setupPrincipalBasedAccessControl(systemPrincipal, testContentJcrPath, JCR_NODE_TYPE_MANAGEMENT);
        setupPrincipalBasedAccessControl(systemPrincipal, null, JCR_NAMESPACE_MANAGEMENT);

        root.commit();

        testRoot = login(new SimpleCredentials(testUser.getID(), testUser.getID().toCharArray())).getLatestRoot();
        testAcMgr = createAccessControlManager(testRoot);
    }

    private static void assertEmptyPolicies(@NotNull AccessControlPolicy[] policies) {
        assertEquals(0, policies.length);
    }

    private static void assertPolicies(@NotNull AccessControlPolicy[] policies, Class<? extends JackrabbitAccessControlList> expectedClass, int expectedSize, int expectedEntrySize) {
        assertEquals(expectedSize, policies.length);
        if (expectedSize > 0) {
            assertTrue(expectedClass.isAssignableFrom(policies[0].getClass()));
            assertEquals(expectedEntrySize, ((JackrabbitAccessControlList) policies[0]).size());
        }
    }

    private static void assertEntry(@NotNull PrincipalPolicyImpl.EntryImpl entry, @Nullable String effectivePath, @NotNull PrivilegeBits expectedBits) {
        assertEquals(expectedBits, entry.getPrivilegeBits());
        if (effectivePath == null) {
            assertNull(entry.getEffectivePath());
        } else {
            assertEquals(effectivePath, entry.getEffectivePath());
        }
    }

    @Test(expected = AccessDeniedException.class)
    public void testGetApplicableByPath() throws RepositoryException {
        testAcMgr.getApplicablePolicies(testJcrPath);
    }

    @Test(expected = AccessDeniedException.class)
    public void testGetPoliciesByPath() throws RepositoryException {
        testAcMgr.getPolicies(testJcrPath);
    }

    @Test(expected = AccessDeniedException.class)
    public void testGetEffectiveByPathNoAccess() throws RepositoryException {
        testAcMgr.getEffectivePolicies(testJcrPath);
    }

    @Test(expected = AccessDeniedException.class)
    public void testGetEffectiveByNullPath() throws RepositoryException {
        testAcMgr.getEffectivePolicies((String) null);
    }

    @Test(expected = AccessDeniedException.class)
    public void testGetEffectiveByRooyPath() throws RepositoryException {
        testAcMgr.getEffectivePolicies(PathUtils.ROOT_PATH);
    }

    @Test(expected = AccessDeniedException.class)
    public void testGetEffectiveByPathReadAccessControlOnPrincipal() throws Exception {
        // grant testuser read-access control on testPrincipal-path but NOT on effective paths null and /oak:content
        addDefaultEntry(systemPrincipalPath, getTestUser().getPrincipal(), JCR_READ_ACCESS_CONTROL);
        root.commit();
        testRoot.refresh();

        // since default permission evaluation is in charge for 'testUser' -> access to full principal policy is now
        // granted
        AccessControlPolicy[] effective = testAcMgr.getEffectivePolicies((String)testJcrPath);
        assertEquals(1, effective.length);
        assertTrue(effective[0] instanceof PrincipalPolicyImpl);
    }

    @Test
    public void testGetEffectiveByPathMissingReadAccessControlOnPrincipal() throws Exception {
        // test-user: granted read-access-control on effective null-path
        addDefaultEntry(null, getTestUser().getPrincipal(), JCR_READ_ACCESS_CONTROL);
        // test-user: granted read-access-control on effective /oak:content
        addDefaultEntry(PathUtils.getAncestorPath(testJcrPath, 3), getTestUser().getPrincipal(), JCR_READ_ACCESS_CONTROL);
        root.commit();
        testRoot.refresh();

        assertEmptyPolicies(testAcMgr.getEffectivePolicies((String) null));
        assertEmptyPolicies(testAcMgr.getEffectivePolicies(testJcrPath));
    }

    @Test(expected = AccessDeniedException.class)
    public void testGetApplicableByPrincipalNoAccess() throws RepositoryException {
        testAcMgr.getApplicablePolicies(systemPrincipal);
    }

    @Test(expected = AccessDeniedException.class)
    public void testGetPoliciesByPrincipalNoAccess() throws RepositoryException {
        testAcMgr.getPolicies(systemPrincipal);
    }

    @Test(expected = AccessDeniedException.class)
    public void testGetEffectiveByPrincipalNoAccess() throws RepositoryException {
        testAcMgr.getEffectivePolicies(ImmutableSet.of(systemPrincipal));
    }

    @Test
    public void testGetPoliciesByPrincipal() throws Exception {
        // grant testuser read-access control on testPrincipal-path but NOT on effective paths null and /oak:content
        addDefaultEntry(systemPrincipalPath, getTestUser().getPrincipal(), JCR_READ_ACCESS_CONTROL);
        root.commit();
        testRoot.refresh();

        assertPolicies(testAcMgr.getPolicies(systemPrincipal), PrincipalPolicyImpl.class, 1, 2);
    }

    @Test
    public void testGetEffectiveByPrincipal() throws Exception {
        // grant testuser read-access control on testPrincipal-path but NOT on effective paths null and /oak:content
        addDefaultEntry(systemPrincipalPath, getTestUser().getPrincipal(), JCR_READ_ACCESS_CONTROL);
        root.commit();
        testRoot.refresh();

        // while read-access-control is granted for the principalpolicy itself by the default permission evalution
        assertPolicies(testAcMgr.getEffectivePolicies(ImmutableSet.of(systemPrincipal)), ImmutableACL.class, 1, 2);
    }

    @Test(expected = AccessDeniedException.class)
    public void testSetPolicyMissingModifyAccessControlOnPrincipal() throws Exception {
        addDefaultEntry(systemPrincipalPath, getTestUser().getPrincipal(), JCR_READ_ACCESS_CONTROL);
        root.commit();
        testRoot.refresh();

        PrincipalPolicyImpl policy = (PrincipalPolicyImpl) testAcMgr.getPolicies(systemPrincipal)[0];
        policy.addEntry(null, privilegesFromNames(JCR_WORKSPACE_MANAGEMENT));

        testAcMgr.setPolicy(policy.getPath(), policy);
    }

    @Test
    public void testSetPolicy() throws Exception {
        addDefaultEntry(systemPrincipalPath, getTestUser().getPrincipal(), JCR_READ_ACCESS_CONTROL, JCR_MODIFY_ACCESS_CONTROL);
        root.commit();
        testRoot.refresh();

        PrincipalPolicyImpl policy = (PrincipalPolicyImpl) testAcMgr.getPolicies(systemPrincipal)[0];
        policy.addEntry(null, privilegesFromNames(JCR_WORKSPACE_MANAGEMENT));
        policy.addEntry(testJcrPath, privilegesFromNames(JCR_READ));

        testAcMgr.setPolicy(policy.getPath(), policy);
    }

    @Test(expected = AccessDeniedException.class)
    public void testRemovePolicyMissingModifyAccessControlOnPrincipal() throws Exception {
        addDefaultEntry(systemPrincipalPath, getTestUser().getPrincipal(), JCR_READ_ACCESS_CONTROL);
        root.commit();
        testRoot.refresh();

        PrincipalPolicyImpl policy = (PrincipalPolicyImpl) testAcMgr.getPolicies(systemPrincipal)[0];
        testAcMgr.removePolicy(policy.getPath(), policy);
    }

    @Test
    public void testRemovePolicy() throws Exception {
        addDefaultEntry(systemPrincipalPath, getTestUser().getPrincipal(), JCR_READ_ACCESS_CONTROL, JCR_MODIFY_ACCESS_CONTROL);
        root.commit();
        testRoot.refresh();

        PrincipalPolicyImpl policy = (PrincipalPolicyImpl) testAcMgr.getPolicies(systemPrincipal)[0];
        testAcMgr.removePolicy(policy.getPath(), policy);
    }
}