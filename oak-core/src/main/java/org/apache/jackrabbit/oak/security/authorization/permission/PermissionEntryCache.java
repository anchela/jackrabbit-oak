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

/**
 * {@code PermissionEntryCache} caches the permission entries of principals.
 * The cache is held locally for each session and contains a version of the principal permission
 * entries of the session that read them last.
 */
class PermissionEntryCache {

    private final Map<String, PrincipalPermissionEntries> entries = new HashMap<String, PrincipalPermissionEntries>();

    @Nonnull
    private PrincipalPermissionEntries getFullyLoadedEntries(@Nonnull PermissionStore store,
                                                             @Nonnull String principalName) {
        PrincipalPermissionEntries ppe = entries.get(principalName);
        if (ppe == null || !ppe.isFullyLoaded()) {
            ppe = store.load(principalName);
            entries.put(principalName, ppe);
        }
        return ppe;
    }

    void load(@Nonnull PermissionStore store,
              @Nonnull String principalName) {
        PrincipalPermissionEntries ppe = getFullyLoadedEntries(store, principalName);
    }

    void load(@Nonnull PermissionStore store,
              @Nonnull String principalName,
              @Nonnull Map<String, Collection<PermissionEntry>> pathEntryMap) {
        PrincipalPermissionEntries ppe = getFullyLoadedEntries(store, principalName);
        for (Map.Entry<String, Collection<PermissionEntry>> e : ppe.getEntries().entrySet()) {
            Collection<PermissionEntry> pathEntries = pathEntryMap.get(e.getKey());
            if (pathEntries == null) {
                pathEntries = new TreeSet<PermissionEntry>(e.getValue());
                pathEntryMap.put(e.getKey(), pathEntries);
            } else {
                pathEntries.addAll(e.getValue());
            }
        }
    }

    void load(@Nonnull PermissionStore store,
              @Nonnull Collection<PermissionEntry> ret,
              @Nonnull String principalName,
              @Nonnull String path) {
        PrincipalPermissionEntries ppe = entries.get(principalName);
        if (ppe == null) {
            ppe = new PrincipalPermissionEntries();
            entries.put(principalName, ppe);
        }
        Collection<PermissionEntry> pes = ppe.getEntriesByPath(path);
        if (ppe.isFullyLoaded() || pes != null) {
            // no need to read from store
            if (pes != null) {
                ret.addAll(pes);
            }
        } else {
            // read entries for path from store
            pes = store.load(null, principalName, path);
            if (pes == null) {
                // nothing to add to the result collection 'ret'.
                // nevertheless, remember the absence of any permission entries
                // in the cache to avoid reading from store again.
                ppe.putEntriesByPath(path, Collections.emptySet());
            } else {
                ppe.putEntriesByPath(path, pes);
                ret.addAll(pes);
            }
        }
    }

    void flush(@Nonnull Set<String> principalNames) {
        entries.keySet().removeAll(principalNames);
    }
}