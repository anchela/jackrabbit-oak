/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.jackrabbit.oak.security.user;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import javax.annotation.Nonnull;

import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import org.apache.jackrabbit.JcrConstants;
import org.apache.jackrabbit.oak.api.PropertyState;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.api.Type;
import org.apache.jackrabbit.oak.plugins.memory.EmptyPropertyState;
import org.apache.jackrabbit.oak.plugins.memory.PropertyStates;
import org.apache.jackrabbit.oak.spi.security.user.UserConstants;

import static com.google.common.base.Preconditions.checkState;
import static org.apache.jackrabbit.oak.api.Type.NAME;

public class MembersPropertyBuilder implements UserConstants {

    private final Tree groupTree;
    private final String treeName;

    private Tree membersTree;
    private final TreeSet<String> values = Sets.newTreeSet();

    private boolean initialized = false;
    private boolean modified = false;

    MembersPropertyBuilder(@Nonnull Tree groupTree) {
        this.groupTree = groupTree;
        this.membersTree = groupTree;
        this.treeName = groupTree.getName();
    }

    MembersPropertyBuilder(@Nonnull Tree groupTree, @Nonnull String treeName) {
        this.groupTree = groupTree;
        this.treeName = treeName;
    }

    /**
     * Create a new instance for building {@code PropertyState} instances
     * of the given {@code type}.
     * @throws IllegalArgumentException if {@code type.isArray()} is {@code true}.
     */
    MembersPropertyBuilder(@Nonnull Tree groupTree, @Nonnull Tree memberTree) {
        this.groupTree = groupTree;
        this.membersTree = memberTree;
        treeName = memberTree.getName();

        initialized = true;
    }


    static MembersPropertyBuilder createNewBuilder(@Nonnull Tree groupTree) {
        MembersPropertyBuilder builder = new MembersPropertyBuilder(groupTree, createMemberReferenceTree(groupTree));
        return builder;
    }

    boolean modified() {
        return modified;
    }

    int size() {
        init();
        return values.size();
    }

    boolean addValue(@Nonnull String value) {
        init();
        return setModified((values.add(value)));
    }

    boolean addValues(@Nonnull Collection<String> values) {
        if (!values.isEmpty()) {
            init();
            return setModified(this.values.addAll(values));
        } else {
            return false;
        }
    }

    boolean removeValue(@Nonnull String value) {
        init();
        return setModified(values.remove(value));
    }

    @Nonnull
    String removeFirst() {
        init();
        String first = values.first();
        setModified(values.remove(first));
        return first;
    }

    boolean build(@Nonnull Map<String, String> updateMap, int threshold)  {
        boolean isEmpty = values.isEmpty();
        if (modified) {
            if (isEmpty) {
                // no values left in this member tree
                // => clean up lookup
                // => remove (unless it's the group tree itself)
                if (groupTree != membersTree) {
                    membersTree.remove();
                } else {
                    groupTree.removeProperty(REP_MEMBERS);
                }
            } else if (values.size() <= threshold+1) {
                // no need to split => write property to the membersTree (avoiding singular values)
                PropertyState ps = buildPropertyState();
                membersTree.setProperty(ps);
                updateMap.put(membersTree.getName(), getLastValue(ps));
            } else {
                // number of values exceeds threshold -> split to multiple properties/trees
                List<PropertyState> states = buildPropertyStates(threshold);
                for (int i = 0; i < states.size(); i++) {
                    Tree t = membersTree;
                    PropertyState ps = states.get(i);
                    if (i == 0) {
                        t.setProperty(ps);
                    } else {
                        t = createMemberReferenceTree(groupTree, ps);
                    }
                    updateMap.put(t.getName(), getLastValue(ps));
                }
            }
            initialized = false;
            values.clear();
        } // else: no need to write back as member-ref property has not changed
        return isEmpty;
    }

    private void init() {
        if (!initialized) {
            PropertyState property = getMembersProperty();
            if (property != null) {
                Iterables.addAll(this.values, property.getValue(Type.WEAKREFERENCES));
            }
        }
        initialized = true;
    }


    private boolean setModified(boolean opResult) {
        if (opResult) {
            modified = true;
        }
        return opResult;
    }

    private PropertyState getMembersProperty() {
        if (membersTree == null) {
            Tree memberList = groupTree.getChild(REP_MEMBERS_LIST);
            if (!memberList.exists() || !memberList.hasChild(treeName) && treeName.equals(groupTree.getName())) {
                membersTree = groupTree;
            } else {
                membersTree = memberList.getChild(treeName);
                checkState(membersTree.exists());
            }
        }
        return membersTree.getProperty(REP_MEMBERS);
    }

    @Nonnull
    private PropertyState buildPropertyState() {
        if (values.isEmpty()) {
            return EmptyPropertyState.emptyProperty(REP_MEMBERS, Type.WEAKREFERENCES);
        } else {
            return PropertyStates.createProperty(REP_MEMBERS, values, Type.WEAKREFERENCES);
        }
    }

    private List<PropertyState> buildPropertyStates(int threshold) {
        Iterable<List<String>> partitions = Iterables.partition(values, threshold/2);
        List<PropertyState> states = Lists.newArrayListWithExpectedSize(Iterables.size(partitions));

        for (List<String> valueList : partitions) {
            PropertyState ps;
            if (valueList.size() == 1 && !states.isEmpty()) {
                // rep:members properties must always contain at least 2 entries
                PropertyState last = states.remove(states.size()-1);
                Iterable<String> values = Iterables.concat(last.getValue(Type.WEAKREFERENCES), valueList);
                ps =  PropertyStates.createProperty(REP_MEMBERS, values, Type.WEAKREFERENCES);
            } else {
                ps = PropertyStates.createProperty(REP_MEMBERS, valueList, Type.WEAKREFERENCES);
            }
            states.add(ps);
        }
        return states;
    }

    private static Tree createMemberReferenceTree(@Nonnull Tree groupTree, @Nonnull PropertyState members) {
        Tree target = createMemberReferenceTree(groupTree);
        target.setProperty(members);
        return target;
    }

    private static Tree createMemberReferenceTree(@Nonnull Tree groupTree) {
        Tree target;
        Tree membersList = groupTree.getChild(REP_MEMBERS_LIST);
        if (!membersList.exists()) {
            membersList = groupTree.addChild(REP_MEMBERS_LIST);
            membersList.setProperty(JcrConstants.JCR_PRIMARYTYPE, NT_REP_MEMBER_REFERENCES_LIST, NAME);
        }
        target = membersList.addChild("m-" + membersList.getChildrenCount(Long.MAX_VALUE));
        target.setProperty(JcrConstants.JCR_PRIMARYTYPE, NT_REP_MEMBER_REFERENCES, NAME);
        return target;
    }

    private static String getLastValue(@Nonnull PropertyState property) {
        return property.getValue(Type.WEAKREFERENCE, property.count()-1);
    }
}
