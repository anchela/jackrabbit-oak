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
package org.apache.jackrabbit.oak.security.authorization.permission;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import javax.annotation.Nonnull;

import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.spi.security.authorization.accesscontrol.AccessControlConstants;
import org.apache.jackrabbit.oak.spi.state.NodeStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final class PermissionCacheBuilder {

    private final PermissionStore store;
    private final PermissionEntryCache peCache;

    PermissionCacheBuilder(@Nonnull PermissionStore store) {
        this.store = store;
        this.peCache = new PermissionEntryCache();
    }

    void init(@Nonnull String principalName, long expectedSize) {
        peCache.init(principalName, expectedSize);
    }

    void load(@Nonnull String principalName) {
        peCache.getFullyLoadedEntries(store, principalName);
    }

    PermissionCache build(@Nonnull Set<String> principalNames, boolean usePathEntryMap) {
        if (principalNames.isEmpty()) {
            return EmptyCache.INSTANCE;
        }
        if (usePathEntryMap) {
            // the total number of access controlled paths is smaller that maxSize,
            // so we can load all permission entries for all principals having
            // any entries right away into the pathEntryMap
            Map<String, Collection<PermissionEntry>> pathEntryMap = new HashMap<>();
            for (String name : principalNames) {
                PrincipalPermissionEntries ppe = peCache.getFullyLoadedEntries(store, name);
                for (Map.Entry<String, Collection<PermissionEntry>> e : ppe.getEntries().entrySet()) {
                    Collection<PermissionEntry> pathEntries = pathEntryMap.get(e.getKey());
                    if (pathEntries == null) {
                        pathEntries = new TreeSet(e.getValue());
                        pathEntryMap.put(e.getKey(), pathEntries);
                    } else {
                        pathEntries.addAll(e.getValue());
                    }
                }
            }
            return new PathEntryMapCache(pathEntryMap);
        } else {
            return new DefaultPermissionCache(store, peCache, principalNames);
        }

    }

    //------------------------------------< PermissionCache Implementations >---
    /**
     * Default implementation of {@code PermissionCache} wrapping the
     * {@code PermissionEntryCache}, which was previously hold as shared field
     * inside the {@code PermissionEntryProviderImpl}
     */
    private static final class DefaultPermissionCache implements PermissionCache {
        private final PermissionStore store;
        private final PermissionEntryCache cache;
        private final Set<String> existingNames;

        DefaultPermissionCache(@Nonnull PermissionStore store, @Nonnull PermissionEntryCache cache, Set<String> existingNames) {
            this.store = store;
            this.cache = cache;
            this.existingNames = existingNames;
        }

        @Override
        public Collection<PermissionEntry> getEntries(@Nonnull String path) {
            Collection<PermissionEntry> ret = new TreeSet();
            for (String name : existingNames) {
                cache.load(store, ret, name, path);
            }
            return ret;
        }

        @Override
        public Collection<PermissionEntry> getEntries(@Nonnull Tree accessControlledTree) {
            return (accessControlledTree.hasChild(AccessControlConstants.REP_POLICY)) ?
                    getEntries(accessControlledTree.getPath()) :
                    Collections.<PermissionEntry>emptyList();
        }
    }

    /**
     * Fixed size implementation of {@code PermissionCache} that holds a map
     * containing all existing entries that in this case have been read eagerly
     * upfront. This implementation replaces the optional {@code pathEntryMap}
     * previously present inside the the {@code PermissionEntryProviderImpl}.
     */
    private static final class PathEntryMapCache implements PermissionCache {
        private final Map<String, Collection<PermissionEntry>> pathEntryMap;

        PathEntryMapCache(Map<String, Collection<PermissionEntry>> pathEntryMap) {
            this.pathEntryMap = pathEntryMap;
        }

        @Override
        public Collection<PermissionEntry> getEntries(@Nonnull String path) {
            Collection<PermissionEntry> entries = pathEntryMap.get(path);
            return (entries != null) ? entries : Collections.<PermissionEntry>emptyList();
        }

        @Override
        public Collection<PermissionEntry> getEntries(@Nonnull Tree accessControlledTree) {
            Collection<PermissionEntry> entries = pathEntryMap.get(accessControlledTree.getPath());
            return (entries != null) ? entries : Collections.<PermissionEntry>emptyList();
        }
    }

    /**
     * Empty implementation of {@code PermissionCache} for those cases where
     * for a given (possibly empty) set of principals no permission entries are
     * present.
     */
    private static final class EmptyCache implements PermissionCache {

        private static final PermissionCache INSTANCE = new EmptyCache();

        @Override
        public Collection<PermissionEntry> getEntries(@Nonnull String path) {
            return Collections.<PermissionEntry>emptyList();
        }

        @Override
        public Collection<PermissionEntry> getEntries(@Nonnull Tree accessControlledTree) {
            return Collections.<PermissionEntry>emptyList();
        }
    }

}