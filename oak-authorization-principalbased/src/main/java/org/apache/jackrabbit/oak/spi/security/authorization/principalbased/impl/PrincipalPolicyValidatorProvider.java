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

import com.google.common.base.Strings;
import com.google.common.collect.Iterables;
import org.apache.jackrabbit.JcrConstants;
import org.apache.jackrabbit.api.security.authorization.PrivilegeManager;
import org.apache.jackrabbit.oak.api.CommitFailedException;
import org.apache.jackrabbit.oak.api.PropertyState;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.api.Type;
import org.apache.jackrabbit.oak.commons.PathUtils;
import org.apache.jackrabbit.oak.namepath.NamePathMapper;
import org.apache.jackrabbit.oak.plugins.nodetype.TypePredicate;
import org.apache.jackrabbit.oak.plugins.tree.TreeUtil;
import org.apache.jackrabbit.oak.spi.commit.CommitInfo;
import org.apache.jackrabbit.oak.spi.commit.DefaultValidator;
import org.apache.jackrabbit.oak.spi.commit.Validator;
import org.apache.jackrabbit.oak.spi.commit.ValidatorProvider;
import org.apache.jackrabbit.oak.spi.commit.VisibleValidator;
import org.apache.jackrabbit.oak.spi.nodetype.NodeTypeConstants;
import org.apache.jackrabbit.oak.spi.security.authorization.AuthorizationConfiguration;
import org.apache.jackrabbit.oak.spi.security.authorization.permission.PermissionProvider;
import org.apache.jackrabbit.oak.spi.state.NodeState;
import org.apache.jackrabbit.oak.spi.state.NodeStateUtils;
import org.jetbrains.annotations.NotNull;

import javax.jcr.RepositoryException;
import javax.jcr.security.AccessControlException;
import javax.jcr.security.Privilege;
import java.security.Principal;
import java.util.Set;

import static org.apache.jackrabbit.oak.api.CommitFailedException.ACCESS;
import static org.apache.jackrabbit.oak.api.CommitFailedException.ACCESS_CONTROL;
import static org.apache.jackrabbit.oak.api.CommitFailedException.CONSTRAINT;
import static org.apache.jackrabbit.oak.api.CommitFailedException.OAK;
import static org.apache.jackrabbit.oak.plugins.tree.factories.RootFactory.createReadOnlyRoot;

class PrincipalPolicyValidatorProvider extends ValidatorProvider implements Constants {

    private final MgrProvider mgrProvider;
    private final Set<Principal> principals;
    private final String workspaceName;

    private PermissionProvider permissionProvider;
    private TypePredicate isMixPrincipalBased;

    PrincipalPolicyValidatorProvider(@NotNull MgrProvider mgrProvider, @NotNull Set<Principal> principals, @NotNull String workspaceName) {
        this.mgrProvider = mgrProvider;
        this.principals = principals;
        this.workspaceName = workspaceName;
    }

    @Override
    protected PolicyValidator getRootValidator(NodeState before, NodeState after, CommitInfo info) {
        permissionProvider = mgrProvider.getSecurityProvider().getConfiguration(AuthorizationConfiguration.class).getPermissionProvider(createReadOnlyRoot(before), workspaceName, principals);
        isMixPrincipalBased = new TypePredicate(after, MIX_REP_PRINCIPAL_BASED_MIXIN);
        return new PolicyValidator(after);
    }

    private final class PolicyValidator extends DefaultValidator {

        private final Tree parentAfter;
        private final boolean isNodetypeTree;

        private PolicyValidator(@NotNull NodeState rootState) {
            mgrProvider.reset(mgrProvider.getRootProvider().createReadOnlyRoot(rootState), NamePathMapper.DEFAULT);
            this.parentAfter = mgrProvider.getTreeProvider().createReadOnlyTree(rootState);
            this.isNodetypeTree = false;
        }

        private PolicyValidator(@NotNull PolicyValidator parentValidator, @NotNull Tree after) {
            this.parentAfter = after;
            if (parentValidator.isNodetypeTree) {
                this.isNodetypeTree = true;
            } else {
                this.isNodetypeTree = NodeTypeConstants.JCR_NODE_TYPES.equals(after.getName()) && NodeTypeConstants.JCR_SYSTEM.equals(parentValidator.parentAfter.getName());
            }
        }

        //------------------------------------------------------< Validator >---
        @Override
        public void propertyAdded(PropertyState after) throws CommitFailedException {
            String propertyName = after.getName();
            if (JcrConstants.JCR_PRIMARYTYPE.equals(propertyName)) {
                if (NT_REP_PRINCIPAL_POLICY.equals(after.getValue(Type.NAME)) && !REP_PRINCIPAL_POLICY.equals(parentAfter.getName())) {
                    throw accessControlViolation(30, "Attempt create policy node with different name than '"+REP_PRINCIPAL_POLICY+"'.");
                }
            }
        }

        @Override
        public void propertyChanged(PropertyState before, PropertyState after) throws CommitFailedException {
            String name = after.getName();
            if (JcrConstants.JCR_PRIMARYTYPE.equals(name)) {
                if (NT_REP_PRINCIPAL_POLICY.equals(before.getValue(Type.STRING)) || NT_REP_PRINCIPAL_POLICY.equals(after.getValue(Type.STRING))) {
                    throw accessControlViolation(31, "Attempt to change primary type of/to rep:PrincipalPolicy.");
                }
            }
        }

        @Override
        public Validator childNodeAdded(String name, NodeState after) throws CommitFailedException {
            if (!isNodetypeTree) {
                if (REP_PRINCIPAL_POLICY.equals(name)) {
                    validatePolicyNode(parentAfter, after);
                } else if (REP_RESTRICTIONS.equals(name)) {
                    validateRestrictions(after);
                } else if (NT_REP_PRINCIPAL_ENTRY.equals(NodeStateUtils.getPrimaryTypeName(after))) {
                    validateEntry(name, after);
                }
            }
            return new VisibleValidator(nextValidator(name, after), true, true);
        }

        @Override
        public Validator childNodeChanged(String name, NodeState before, NodeState after) throws CommitFailedException {
            if (!isNodetypeTree) {
                if (after.hasChildNode(REP_PRINCIPAL_POLICY)) {
                    Tree parent = mgrProvider.getTreeProvider().createReadOnlyTree(parentAfter, name, after);
                    validatePolicyNode(parent, after.getChildNode(REP_PRINCIPAL_POLICY));
                } else if (REP_RESTRICTIONS.equals(name)) {
                    validateRestrictions(after);
                } else if (NT_REP_PRINCIPAL_ENTRY.equals(NodeStateUtils.getPrimaryTypeName(after))) {
                    validateEntry(name, after);
                }
            }
            return new VisibleValidator(nextValidator(name, after), true, true);
        }

        //----------------------------------------------------------------------
        private void validatePolicyNode(@NotNull Tree parent, @NotNull NodeState nodeState) throws CommitFailedException {
            if (!NT_REP_PRINCIPAL_POLICY.equals(NodeStateUtils.getPrimaryTypeName(nodeState))) {
                throw accessControlViolation(32, "Reserved node name 'rep:principalPolicy' must only be used for nodes of type 'rep:PrincipalPolicy'.");
            }
            if (!isMixPrincipalBased.apply(parent)) {
                throw accessControlViolation(33, "Parent node not of mixin type 'rep:PrincipalBasedMixin'.");
            }
        }

        private void validateRestrictions(@NotNull NodeState nodeState) throws CommitFailedException {
            if (!NT_REP_RESTRICTIONS.equals(NodeStateUtils.getPrimaryTypeName(nodeState))) {
                throw accessControlViolation(34, "Reserved node name 'rep:restrictions' must only be used for nodes of type 'rep:Restrictions'.");
            }
            if (NT_REP_PRINCIPAL_ENTRY.equals(TreeUtil.getPrimaryTypeName(parentAfter))) {
                try {
                    String oakPath = Strings.emptyToNull(TreeUtil.getString(parentAfter, REP_EFFECTIVE_PATH));
                    mgrProvider.getRestrictionProvider().validateRestrictions(oakPath, parentAfter);
                } catch (AccessControlException e) {
                    throw new CommitFailedException(ACCESS_CONTROL, 35, "Invalid restrictions", e);
                } catch (RepositoryException e) {
                    throw new CommitFailedException(OAK, 13, "Internal error", e);
                }
            } else {
                // assert the restrictions node resides within access control content
                if (!mgrProvider.getContext().definesTree(parentAfter)) {
                    throw new CommitFailedException(ACCESS_CONTROL, 2, "Expected access control entry parent (isolated restriction).");
                }
            }
        }

        private void validateEntry(@NotNull String name, @NotNull NodeState nodeState) throws CommitFailedException {
            String entryPath = PathUtils.concat(parentAfter.getPath(), name);
            if (!REP_PRINCIPAL_POLICY.equals(parentAfter.getName())) {
                throw accessControlViolation(36, "Isolated entry of principal policy at " + entryPath);
            }
            Iterable<String> privilegeNames = nodeState.getNames(REP_PRIVILEGES);
            if (Iterables.isEmpty(privilegeNames)) {
                throw accessControlViolation(37, "Empty rep:privileges property at " + entryPath);
            }
            PrivilegeManager privilegeManager = mgrProvider.getPrivilegeManager();
            for (String privilegeName : privilegeNames) {
                try {
                    Privilege privilege = privilegeManager.getPrivilege(privilegeName);
                    if (privilege.isAbstract()) {
                        throw accessControlViolation(38, "Abstract privilege " + privilegeName + " at " + entryPath);
                    }
                } catch (AccessControlException e) {
                    throw accessControlViolation(39, "Invalid privilege " + privilegeName + " at " + entryPath);
                } catch (RepositoryException e) {
                    throw new CommitFailedException(OAK, 13, "Internal error", e);
                }
            }
            // check mod-access-control permission on the effective path
            PropertyState effectivePath = nodeState.getProperty(REP_EFFECTIVE_PATH);
            if (effectivePath == null) {
                throw new CommitFailedException(CONSTRAINT, 21, "Missing mandatory rep:effectivePath property at " + entryPath);
            }
            if (!Utils.hasModAcPermission(permissionProvider, effectivePath.getValue(Type.PATH))) {
                throw new CommitFailedException(ACCESS, 3, "Access denied");
            }
        }

        private CommitFailedException accessControlViolation(int code, String message) {
            return new CommitFailedException(ACCESS_CONTROL, code, message);
        }

        private PolicyValidator nextValidator(@NotNull String name, @NotNull NodeState nodeState) {
            Tree readOnly = mgrProvider.getTreeProvider().createReadOnlyTree(parentAfter, name, nodeState);
            return new PolicyValidator(this, readOnly);
        }
    }
}
