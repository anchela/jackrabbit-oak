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
package org.apache.jackrabbit.oak.security.user;

import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;

import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import org.apache.jackrabbit.oak.api.PropertyState;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.api.Type;
import org.apache.jackrabbit.util.Text;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @see MembershipProvider to more details.
 */
class MembershipWriterV2 extends MembershipWriter  {

    private static final Logger log = LoggerFactory.getLogger(MembershipWriterV2.class);

    /**
     * Adds a new member to the given {@code groupTree}.
     *
     * @param groupTree the group to add the member to
     * @param memberIds the ids of the new members as map of 'contentId':'memberId'
     * @return the set of member IDs that was not successfully processed.
     */
    Set<String> addMembers(@Nonnull Tree groupTree, @Nonnull Map<String, String> memberIds) {
        Set<String> failedIds = Sets.newHashSetWithExpectedSize(memberIds.size());
        TreeSet<String> contentIds = Sets.newTreeSet(memberIds.keySet());

        TreeMap<String, String> lookup = readLookup(groupTree);
        Map<String, String> update = Maps.newHashMap();

        // collect all ids that are already member, remove them from the memberIds
        // map and insert the others to the best-matching tree
        if (!groupTree.hasChild(REP_MEMBERS_LIST)) {
            // group without any members or members in a single rep:members property
            // at the group tree -> simplified version to add members
            MembersPropertyBuilder builder = new MembersPropertyBuilder(groupTree);
            for (String contentId : contentIds) {
                if (!builder.addValue(contentId)) {
                    failedIds.add(memberIds.remove(contentId));
                }
            }
            builder.build(update, membershipSizeThreshold);
        } else {
            // multiple rep:members properties exist

            MembersPropertyBuilder builder = null;
            for (Map.Entry<String, String> entry : lookup.entrySet()) {
                String lastMemberRef = entry.getKey();
                String treeName = entry.getValue();

                builder = new MembersPropertyBuilder(groupTree, treeName);

                Iterator<String> it = contentIds.iterator();
                while (it.hasNext()) {
                    String contentId = it.next();
                    if (lastMemberRef.equals(contentId)) {
                        // contentId equals to last element in the array
                        it.remove();
                        failedIds.add(memberIds.remove(contentId));
                    } else if (contentId.compareTo(lastMemberRef) < 0) {
                        // contentId belongs to the range defined by this property
                        // => insert or record if it is already contained.
                        it.remove();
                        if (!builder.addValue(contentId)) {
                            failedIds.add(memberIds.remove(contentId));
                        }
                    } else {
                        // stop iteration as all remaining contentIds will either
                        // go into another member-ref-tree or will be appended below
                        break;
                    }
                }

                // write back this builder
                builder.build(update, membershipSizeThreshold);
                // stop looking at other trees if there are no more ids to process
                if (contentIds.isEmpty()) {
                    break;
                }
            }

            if (!contentIds.isEmpty()) {
                MembersPropertyBuilder b;
                if (builder != null) {
                    // append all remaining ids and build (again)
                    b = builder;
                } else {
                    // process remaining contentIds by adding one or multiple new member-ref
                    // trees (depending of the size of contentIds-set) and populating their
                    // rep:members property with the remaining values.
                    b = MembersPropertyBuilder.createNewBuilder(groupTree);
                }
                b.addValues(contentIds);
                b.build(update, membershipSizeThreshold);
            }
        }

        updateLookup(lookup, update, null);
        writeLookup(groupTree, lookup);

        return failedIds;
    }

    /**
     * Removes the members from the given group.
     *
     * @param groupTree group to remove the member from
     * @param memberIds Map of 'contentId':'memberId' of all members that need to be removed.
     * @return the set of member IDs that was not successfully processed.
     */
    Set<String> removeMembers(@Nonnull Tree groupTree, @Nonnull Map<String, String> memberIds) {
        Set<String> contentIds = Sets.newTreeSet(memberIds.keySet());

        TreeMap<String, String> lookup = readLookup(groupTree);
        Map<String, String> update = Maps.newHashMap();
        Set<String> remove = Sets.newHashSet();

        MembersPropertyBuilder previous = null;
        for (Map.Entry<String, String> entry : lookup.entrySet()) {
            String lastMemberRef = entry.getKey();
            String treeName = entry.getValue();

            MembersPropertyBuilder builder = new MembersPropertyBuilder(groupTree, treeName);

            Iterator<String> it = contentIds.iterator();
            while (it.hasNext()) {
                String contentId = it.next();
                int compare = contentId.compareTo(lastMemberRef);
                if (compare <= 0) {
                    // is or might be contained -> try to remove from builder
                    it.remove();
                    if (builder.removeValue(contentId)) {
                        memberIds.remove(contentId);
                    }
                } else {
                    // stop iteration as all remaining contentIds will either
                    // go into another member-ref-tree or will be appended below
                    break;
                }
            }

            if (builder.modified() && builder.size() == 1 && previous != null) {
                previous.addValue(builder.removeFirst());
                previous.build(update, membershipSizeThreshold);
            }

            if (builder.build(update, membershipSizeThreshold)) {
                // => remember for removal from lookup
                remove.add(lastMemberRef);
            }
            previous = builder;
        }
        updateLookup(lookup, update, remove);
        writeLookup(groupTree, lookup);

        return Sets.newHashSet(memberIds.values());
    }

    private static void updateLookup(@Nonnull TreeMap<String, String> lookup, @Nonnull Map<String, String> update, @CheckForNull Set<String> remove) {
        Map<String, String> toAdd = Maps.newHashMapWithExpectedSize(update.size());
        Iterator<Map.Entry<String, String>> it = lookup.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, String> entry = it.next();
            String treeName = entry.getValue();
            String lastVal = entry.getKey();

            String newLastVal = update.remove(treeName);
            if (newLastVal != null && !newLastVal.equals(lastVal)) {
                toAdd.put(newLastVal, treeName);
                it.remove();
            }
        }

        lookup.putAll(toAdd);
        for (Map.Entry<String, String> entry : update.entrySet()) {
            lookup.put(entry.getValue(), entry.getKey());
        }

        if (remove != null) {
            lookup.keySet().removeAll(remove);
        }
    }

    private static TreeMap<String, String> readLookup(@Nonnull Tree groupTree) {
        PropertyState property = groupTree.getProperty(REP_MEMBER_REFERENCES_LOOKUP);
        if (property == null) {
            return Maps.newTreeMap();
        } else {
            String s = property.getValue(Type.STRING);
            TreeMap<String, String> lookup = Maps.newTreeMap();
            for (String entry : Text.explode(s, '/')) {
                String[] strs = Text.explode(entry, '|');
                if (strs.length == 2) {
                    lookup.put(strs[0], strs[1]);
                } else {
                    log.error("TODO");
                }
            }
            return lookup;
        }
    }

    private static void writeLookup(@Nonnull Tree groupTree, @Nonnull TreeMap<String, String> lookup) {
        String[] strs = new String[lookup.size()];
        int i = 0;
        for (Map.Entry<String, String> entry : lookup.entrySet()) {
            strs[i++] = entry.getKey() + '|' +entry.getValue();
        }
        groupTree.setProperty(REP_MEMBER_REFERENCES_LOOKUP, Text.implode(strs, "/"), Type.STRING);
    }
}