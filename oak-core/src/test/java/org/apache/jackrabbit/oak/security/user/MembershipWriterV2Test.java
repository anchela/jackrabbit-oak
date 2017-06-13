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
import java.util.List;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import com.google.common.base.Function;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.google.common.collect.Iterators;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import org.apache.jackrabbit.api.security.user.Group;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.oak.api.PropertyState;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.api.Type;
import org.apache.jackrabbit.oak.spi.security.user.UserConstants;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertTrue;
import static org.junit.Assert.assertNotNull;

/**
 * @since OAK 1.8
 */
public class MembershipWriterV2Test extends MembershipWriterTest {

    @Before
    public void before() throws Exception {
        super.before();
        writer = new MembershipWriterV2();
        // set the threshold low for testing
        writer.setMembershipSizeThreshold(SIZE_TH);
    }

    private static Map<String, String> getRemoveMap(@Nonnull Tree tree, @Nonnull final Map<String, String> idLookup) {
        return Maps.asMap(Sets.newHashSet(tree.getProperty(REP_MEMBERS).getValue(Type.WEAKREFERENCES)), new Function<String, String>() {
            @Nullable
            @Override
            public String apply(String input) {
                return idLookup.get(input);
            }
        });
    }

    @Ignore
    @Test
    public void testAddMemberExceedThreshold() throws Exception {
        // TODO
    }

    @Ignore
    @Test
    public void testAddMembersExceedThreshold() throws Exception {
        // TODO
    }

    @Ignore
    @Test
    public void testAddMembersExceedThreshold2() throws Exception {
        // TODO
    }

    @Ignore
    @Test
    public void testRemoveMembers() throws Exception {
        final Map<String, String> memberIds = Maps.newHashMap();
        String[] userIds = new String[NUM_USERS];

        Group grp = createGroup();
        Tree grpTree = getTree(grp);

        for (int i = 0; i < NUM_USERS; i++) {
            User usr = createUser();
            memberIds.put(getContentID(usr.getID()), usr.getID());
            userIds[i] = usr.getID();
        }
        assertTrue(addMembers(grpTree, ImmutableList.copyOf(userIds)).isEmpty());
        assertMembers(grp, memberIds.values());

        // remove the members that are contained in the rep:members properties of the the group node
        // the rep:members property; remember the userIDs that get removed for later re-add
        Map<String, String> toRemove = getRemoveMap(grpTree, memberIds);
        assertEquals(SIZE_TH, toRemove.size());

        List<String> toAdd = Lists.newArrayList(toRemove.values());
        memberIds.keySet().removeAll(toRemove.keySet());

        assertTrue(writer.removeMembers(grpTree, toRemove).isEmpty());
        root.commit();

        // verify storage structure (rep:members property with group tree should be gone) and membership
        assertFalse("rep:members property not exist", grpTree.hasProperty(REP_MEMBERS));
        assertMembers(grp, memberIds.values());

        // now add half of the removed members again.
        int cnt = toAdd.size()/2;
        for (int i = 0; i < cnt; i++) {
            memberIds.put(getContentID(userIds[i]), userIds[i]);
        }
        assertTrue(addMembers(grpTree, Iterables.limit(toAdd, cnt)).isEmpty());

        PropertyState repMembers = grpTree.getProperty(REP_MEMBERS);
        assertNotNull(repMembers);
        assertEquals("rep:members property must have correct number of references", cnt, repMembers.count());
        assertMembers(grp, memberIds.values());

        // now remove the users from the first overflow node
        Iterator<Tree> it = grpTree.getChild(REP_MEMBERS_LIST).getChildren().iterator();
        Tree t = it.next();
        String name = t.getName();

        toRemove = getRemoveMap(t, memberIds);
        toAdd = Lists.newArrayList(toRemove.values());
        memberIds.keySet().removeAll(toRemove.keySet());

        writer.removeMembers(grpTree, toRemove);
        root.commit();

        assertMembers(grp, memberIds.values());

        Tree membersList = grpTree.getChild(REP_MEMBERS_LIST);
        assertFalse("the first overflow node must not exist", membersList.hasChild(name));

        // now add 10 users and check if the "1" node exists again
        //toAdd = Sets.newHashSet();
        for (int i = 2 * SIZE_TH; i < (3 * SIZE_TH); i++) {
            memberIds.put(getContentID(userIds[i]), userIds[i]);
            toAdd.add(userIds[i]);
        }
        assertTrue(addMembers(grpTree, toAdd).isEmpty());
        assertMembers(grp, memberIds.values());

        membersList = grpTree.getChild(REP_MEMBERS_LIST);
        assertTrue("the first overflow node must not exist", membersList.getChild("1").exists());
    }

    @Test
    public void testAddMembersLowerThreshold() throws Exception {
        final Map<String, String> m = Maps.newHashMap();
        Tree grpTree = getTree(createGroup());

        for (int i = 0; i < SIZE_TH/2; i++) {
            User usr = createUser();
            m.put(getContentID(usr.getID()), usr.getID());
        }

        assertTrue(writer.addMembers(grpTree, m).isEmpty());

        assertTrue(grpTree.hasProperty(REP_MEMBERS));
        assertFalse(grpTree.hasChild(REP_MEMBERS_LIST));

        Iterable<String> expected = Sets.newTreeSet(m.keySet());
        assertTrue(Iterables.elementsEqual(expected, grpTree.getProperty(REP_MEMBERS).getValue(Type.WEAKREFERENCES)));
    }


    @Test
    public void testAddMembersThreshold() throws Exception {
        final Map<String, String> m = Maps.newHashMap();
        Tree grpTree = getTree(createGroup());

        for (int i = 0; i < SIZE_TH; i++) {
            User usr = createUser();
            m.put(getContentID(usr.getID()), usr.getID());
        }

        assertTrue(writer.addMembers(grpTree, m).isEmpty());

        assertTrue(grpTree.hasProperty(REP_MEMBERS));
        assertFalse(grpTree.hasChild(REP_MEMBERS_LIST));

        Iterable<String> expected = Sets.newTreeSet(m.keySet());
        assertTrue(Iterables.elementsEqual(expected, grpTree.getProperty(REP_MEMBERS).getValue(Type.WEAKREFERENCES)));
    }

    @Test
    public void testAddMembersThresholdPlus1() throws Exception {
        final Map<String, String> m = Maps.newHashMap();
        Tree grpTree = getTree(createGroup());

        for (int i = 0; i < SIZE_TH + 1; i++) {
            User usr = createUser();
            m.put(getContentID(usr.getID()), usr.getID());
        }

        assertTrue(writer.addMembers(grpTree, m).isEmpty());

        assertTrue(grpTree.hasProperty(REP_MEMBERS));
        assertFalse(grpTree.hasChild(REP_MEMBERS_LIST));
    }

    @Ignore
    @Test
    public void testAddMembersThresholdPlus2() throws Exception {
        final Map<String, String> m = Maps.newHashMap();
        Tree grpTree = getTree(createGroup());

        for (int i = 0; i < SIZE_TH + 2; i++) {
            User usr = createUser();
            m.put(getContentID(usr.getID()), usr.getID());
        }

        assertTrue(writer.addMembers(grpTree, m).isEmpty());

        assertTrue(grpTree.hasProperty(REP_MEMBERS));
        assertTrue(grpTree.hasChild(REP_MEMBERS_LIST));

        Tree list = grpTree.getChild(REP_MEMBERS_LIST);
        assertEquals(1, list.getChildrenCount(10));

        Iterable<String> expectedInOverflow = Lists.newArrayList(Sets.newTreeSet(m.keySet())).subList(SIZE_TH, m.size());
        PropertyState overflowProp = list.getChildren().iterator().next().getProperty(REP_MEMBERS);

        assertNotNull(overflowProp);
        assertTrue(Iterables.elementsEqual(expectedInOverflow, overflowProp.getValue(Type.WEAKREFERENCES)));
    }

    @Test
    public void testAddMembersOrderedInsertion() throws Exception {
        final Map<String, String> m = Maps.newHashMap();
        Tree grpTree = getTree(createGroup());

        for (int i = 0; i < NUM_USERS; i++) {
            User usr = createUser();
            m.put(getContentID(usr.getID()), usr.getID());
        }
        assertTrue(writer.addMembers(grpTree, m).isEmpty());

        TreeSet<String> expected = Sets.newTreeSet(m.keySet());

        // FIXME: following links instead of relying on child-order which doesn't exist
        Tree membersList = grpTree.getChild(UserConstants.REP_MEMBERS_LIST);
        Iterator<PropertyState> memberProperties = Iterators.transform(Iterators.concat(
                Iterators.singletonIterator(grpTree),
                membersList.getChildren().iterator()
        ), new Function<Tree, PropertyState>() {
            @Override
            public PropertyState apply(Tree input) {
                return input.getProperty(REP_MEMBERS);
            }
        });

        while (memberProperties.hasNext()) {
            List<String> values = Lists.newArrayList(memberProperties.next().getValue(Type.WEAKREFERENCES));
            SortedSet<String> sub = expected.subSet(values.get(0), true, values.get(values.size()-1), true);
            assertTrue(Iterables.elementsEqual(sub, values));
        }
    }

    @Test
    public void testAddMemberOrderedInsertion() throws Exception {
        final Map<String, String> m = Maps.newHashMap();
        Tree grpTree = getTree(createGroup());

        for (int i = 0; i < NUM_USERS; i++) {
            User usr = createUser();
            m.put(getContentID(usr.getID()), usr.getID());
        }
        for (String key : m.keySet()) {
            assertTrue(writer.addMember(grpTree, key));
        }

        TreeSet<String> expected = Sets.newTreeSet(m.keySet());

        // FIXME: following links instead of relying on child-order which doesn't exist
        Tree membersList = grpTree.getChild(UserConstants.REP_MEMBERS_LIST);
        Iterator<PropertyState> memberProperties = Iterators.transform(Iterators.concat(
                Iterators.singletonIterator(grpTree),
                membersList.getChildren().iterator()
        ), new Function<Tree, PropertyState>() {
            @Override
            public PropertyState apply(Tree input) {
                return input.getProperty(REP_MEMBERS);
            }
        });

        while (memberProperties.hasNext()) {
            List<String> values = Lists.newArrayList(memberProperties.next().getValue(Type.WEAKREFERENCES));
            SortedSet<String> sub = expected.subSet(values.get(0), true, values.get(values.size()-1), true);
            assertTrue(Iterables.elementsEqual(sub, values));
        }
    }


    // TODO removal of rep:members
    // TODO removal of member-ref-tree if empty


}