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
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import javax.annotation.Nonnull;

import com.google.common.base.Strings;
import org.apache.jackrabbit.commons.iterator.AbstractLazyIterator;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.commons.LongUtils;
import org.apache.jackrabbit.oak.spi.security.ConfigurationParameters;
import org.apache.jackrabbit.oak.spi.security.authorization.accesscontrol.AccessControlConstants;

class PermissionEntryProviderImpl implements PermissionEntryProvider {

    public static final String EAGER_CACHE_SIZE_PARAM = "eagerCacheSize";

    private static final long DEFAULT_SIZE = 250;

    private static final long MAX_PATHS_SIZE = 10;

    /**
     * The set of principal names for which this {@code PermissionEntryProvider}
     * has been created.
     */
    private final Set<String> principalNames;

    /**
     * The set of principal names for which the store contains any permission
     * entries. This set is equals or just a subset of the {@code principalNames}
     * defined above. The methods collecting the entries will shortcut in case
     * this set is empty and thus no permission entries exist for the specified
     * set of principal.
     */
    private final Set<String> existingNames = new HashSet();

    private final PermissionStore store;

    private final long maxSize;

    private PermissionCache permissionCache;

    PermissionEntryProviderImpl(@Nonnull PermissionStore store, @Nonnull Set<String> principalNames, @Nonnull ConfigurationParameters options) {
        this.store = store;
        this.principalNames = Collections.unmodifiableSet(principalNames);
        this.maxSize = options.getConfigValue(EAGER_CACHE_SIZE_PARAM, DEFAULT_SIZE);
        init();
    }

    private void init() {
        PermissionCacheBuilder builder = new PermissionCacheBuilder(store);

        long cnt = 0;
        existingNames.clear();
        for (String name : principalNames) {
            NumEntries ne = store.getNumEntries(name, maxSize);
            long n = ne.size;
            /*
            if getNumEntries (n) returns a number bigger than 0, we
            remember this principal name int the 'existingNames' set
            */
            if (n > 0) {
                existingNames.add(name);
                if (n <= MAX_PATHS_SIZE) {
                    builder.load(name);
                } else {
                    long expectedSize = (ne.isExact) ? n : Long.MAX_VALUE;
                    builder.init(name, expectedSize);
                }
            }
            /*
            Estimate the total number of access controlled paths (cnt) defined
            for the given set of principals in order to be able to determine if
            the pathEntryMap should be loaded upfront.
            Note however that cache.getNumEntries (n) may return Long.MAX_VALUE
            if the underlying implementation does not know the exact value, and
            the child node count is higher than maxSize (see OAK-2465).
            */                        
            if (cnt < Long.MAX_VALUE) {
                if (Long.MAX_VALUE == n) {
                    cnt = Long.MAX_VALUE;
                } else {
                    cnt = LongUtils.safeAdd(cnt, n);
                }
            }
        }

        boolean usePathEntryMap = (cnt > 0 && cnt < maxSize);
        permissionCache = builder.build(existingNames, usePathEntryMap);
    }

    //--------------------------------------------< PermissionEntryProvider >---
    @Override
    public void flush() {
        init();
    }

    @Override
    @Nonnull
    public Iterator<PermissionEntry> getEntryIterator(@Nonnull EntryPredicate predicate) {
        if (existingNames.isEmpty()) {
            return Collections.emptyIterator();
        } else {
            return new EntryIterator(predicate);
        }
    }

    @Override
    @Nonnull
    public Collection<PermissionEntry> getEntries(@Nonnull Tree accessControlledTree) {
        return permissionCache.getEntries(accessControlledTree);
    }

    //------------------------------------------------------------< private >---
    @Nonnull
    private Collection<PermissionEntry> getEntries(@Nonnull String path) {
        return permissionCache.getEntries(path);
    }

    private final class EntryIterator extends AbstractLazyIterator<PermissionEntry> {

        private final EntryPredicate predicate;

        // the ordered permission entries at a given path in the hierarchy
        private Iterator<PermissionEntry> nextEntries = Collections.emptyIterator();

        // the next oak path for which to retrieve permission entries
        private String path;

        private EntryIterator(@Nonnull EntryPredicate predicate) {
            this.predicate = predicate;
            this.path = Strings.nullToEmpty(predicate.getPath());
        }

        @Override
        protected PermissionEntry getNext() {
            PermissionEntry next = null;
            while (next == null) {
                if (nextEntries.hasNext()) {
                    PermissionEntry pe = nextEntries.next();
                    if (predicate.apply(pe)) {
                        next = pe;
                    }
                } else {
                    if (path == null) {
                        break;
                    }
                    nextEntries = getEntries(path).iterator();
                    path = PermissionUtil.getParentPathOrNull(path);
                }
            }
            return next;
        }
    }
}