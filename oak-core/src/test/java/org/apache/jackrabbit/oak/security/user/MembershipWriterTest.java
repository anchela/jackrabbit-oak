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

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nonnull;

import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import org.apache.jackrabbit.JcrConstants;
import org.apache.jackrabbit.api.security.user.Group;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.oak.api.PropertyState;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.api.Type;
import org.apache.jackrabbit.oak.plugins.tree.TreeUtil;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertTrue;
import static org.junit.Assert.assertNotNull;


/**
 * Test {@code MembershipWriter} and content structure generated by it.
 *
 * @since OAK 1.0
 */
public class MembershipWriterTest extends MembershipBaseTest {

    MembershipWriter writer;

    @Before
    public void before() throws Exception {
        super.before();
        writer = new MembershipWriter();
        // set the threshold low for testing
        writer.setMembershipSizeThreshold(SIZE_TH);
    }

    private static void assertContentStructure(@Nonnull Tree groupTree, int memberCnt) {
        PropertyState members = groupTree.getProperty(REP_MEMBERS);
        assertNotNull(members);
        assertEquals("rep:members property must have correct number of references", SIZE_TH, members.count());

        Tree membersList = groupTree.getChild(REP_MEMBERS_LIST);
        assertTrue("rep:memberList must exist", membersList.exists());

        assertPrimaryType(membersList, NT_REP_MEMBER_REFERENCES_LIST);
        assertEquals("rep:memberList must have correct number of child nodes.", (memberCnt / SIZE_TH) - 1, membersList.getChildrenCount(Long.MAX_VALUE));
        for (Tree memberRefTree : membersList.getChildren()) {
            assertPrimaryType(memberRefTree, NT_REP_MEMBER_REFERENCES);
            assertTrue(memberRefTree.hasProperty(REP_MEMBERS));
        }
    }

    private static void assertPrimaryType(@Nonnull Tree tree, String primaryTypeName) {
        PropertyState primaryType = tree.getProperty(JcrConstants.JCR_PRIMARYTYPE);
        assertNotNull(primaryType);
        assertEquals(tree.getName() + " must have correct primary type.", primaryTypeName, primaryType.getValue(Type.STRING));
    }

    @Test
    public void testAddMemberExceedThreshold() throws Exception {
        Group grp = createGroup();
        for (String contentId : createIdMap(0, NUM_USERS).keySet()) {
            writer.addMember(getTree(grp), contentId);
        }
        root.commit();

        // check storage structure
        assertContentStructure(getTree(grp), NUM_USERS);
    }

    @Test
    public void testAddMembersExceedThreshold() throws Exception {
        Group grp = createGroup();
        Map idMap = createIdMap(0, NUM_USERS);
        writer.addMembers(getTree(grp), idMap);
        root.commit();

        // check storage structure
        assertContentStructure(getTree(grp), NUM_USERS);
    }

    @Test
    public void testAddMembersExceedThreshold2() throws Exception {
        Tree groupTree = getTree(createGroup());

        // 1. add array of 21 memberIDs exceeding the threshold
        Map<String, String> memberIds = createIdMap(0, 21);
        writer.addMembers(groupTree, memberIds);

        PropertyState repMembers = groupTree.getProperty(REP_MEMBERS);
        assertNotNull(repMembers);
        assertEquals(SIZE_TH, repMembers.count());

        // the members-list must how have two ref-members nodes one with 10 and
        // one with a single ref-value
        assertMemberList(groupTree, 2, 1);

        // 2. add more members without reaching threshold => still 2 ref-nodes
        memberIds = createIdMap(21, 29);
        writer.addMembers(groupTree, memberIds);
        assertMemberList(groupTree, 2, 9);

        // 3. fill up second ref-members node => a new one must be created
        memberIds = createIdMap(29, 35);
        writer.addMembers(groupTree, memberIds);
        assertMemberList(groupTree, 3, 5);

        // 4. remove members from the initial set => ref nodes as before, rep:members prop on group modified
        memberIds.clear();
        memberIds.put(getContentID("member1"), "member1");
        memberIds.put(getContentID("member2"), "member2");
        writer.removeMembers(groupTree, Maps.newHashMap(memberIds));

        assertMemberList(groupTree, 3, 5);
        assertEquals(8, groupTree.getProperty(REP_MEMBERS).count());

        // 5. add members again => best-tree is the ref-member-node
        memberIds = createIdMap(35, 39);
        writer.addMembers(groupTree, memberIds);

        assertEquals(8, groupTree.getProperty(REP_MEMBERS).count());
        assertMemberList(groupTree, 3, 9);

        // 6. adding more members will fill up rep:members again and create new ref-node
        memberIds = createIdMap(39, 45);
        writer.addMembers(groupTree, memberIds);

        assertEquals(SIZE_TH, groupTree.getProperty(REP_MEMBERS).count());
        assertEquals(4, groupTree.getChild(REP_MEMBERS_LIST).getChildrenCount(10));
    }

    @Test
    public void testAddMemberAgain() throws Exception {
        Group grp = createGroup();
        List<String> memberPaths = createMembers(grp, NUM_USERS);
        root.commit();

        Tree groupTree = getTree(grp);
        for (String path : memberPaths) {
            Tree memberTree = root.getTree(path);
            String contentId = getContentID(memberTree);
            String memberId = TreeUtil.getString(memberTree, REP_AUTHORIZABLE_ID);
            assertFalse(memberId, writer.addMember(groupTree, contentId));
        }
    }

    @Test
    public void testAddMembersAgain() throws Exception {
        Group grp = createGroup();
        List<String> memberPaths = createMembers(grp, NUM_USERS);
        root.commit();

        Map<String, String> m = new HashMap();
        for (String path : memberPaths) {
            Tree memberTree = root.getTree(path);
            String memberId = TreeUtil.getString(memberTree, REP_AUTHORIZABLE_ID);
            m.put(getContentID(memberTree), memberId);
        }

        Set<String> expected = Sets.newHashSet(m.values());
        Set<String> failed = writer.addMembers(getTree(grp), m);
        assertFalse(failed.isEmpty());
        assertEquals(Sets.difference(expected, failed).toString(), expected, failed);
    }

    @Test
    public void testAddFewMembers() throws Exception {
        Group g = createGroup();
        g.addMembers(createGroup().getID(), createUser().getID());

        assertFalse(getTree(g).hasChild(REP_MEMBERS_LIST));
    }

    @Test
    public void testRemoveMembers() throws Exception {
        Set<String> memberIds = Sets.newLinkedHashSet();
        String[] userIds = new String[NUM_USERS];
        Group grp = createGroup();
        Tree grpTree = getTree(grp);

        for (int i = 0; i < NUM_USERS; i++) {
            User usr = createUser();
            memberIds.add(usr.getID());
            userIds[i] = usr.getID();
        }
        assertTrue(addMembers(grpTree, memberIds).isEmpty());

        // remove the first TH users, this should remove all references from rep:members in the group node and remove
        // the rep:members property
        Map<String, String> toRemove = Maps.newHashMapWithExpectedSize(SIZE_TH);
        for (int i = 0; i < SIZE_TH; i++) {
            String userId = userIds[i];
            memberIds.remove(userId);
            toRemove.put(getContentID(userId), userId);
        }
        writer.removeMembers(grpTree, toRemove);
        root.commit();

        assertMembers(grp, memberIds);

        // also check storage structure: rep:members property with group tree should be gone
        assertFalse("rep:members property not exist", grpTree.hasProperty(REP_MEMBERS));

        // now add TH/2 again.
        Set<String> toAdd = Sets.newHashSet();
        for (int i = 0; i < SIZE_TH / 2; i++) {
            memberIds.add(userIds[i]);
            toAdd.add(userIds[i]);
        }
        assertTrue(addMembers(grpTree, toAdd).isEmpty());

        PropertyState repMembers = grpTree.getProperty(REP_MEMBERS);
        assertNotNull(repMembers);
        assertEquals("rep:members property must have correct number of references", SIZE_TH / 2, repMembers.count());
        assertMembers(grp, memberIds);

        // now remove the users 20-30, this should remove the 2nd overflow node
        toRemove = Maps.newHashMapWithExpectedSize(SIZE_TH);
        for (int i = 2 * SIZE_TH; i < (3 * SIZE_TH); i++) {
            String userId = userIds[i];
            memberIds.remove(userId);
            toRemove.put(getContentID(userId), userId);
        }
        writer.removeMembers(grpTree, toRemove);
        root.commit();

        assertMembers(grp, memberIds);

        Tree membersList = grpTree.getChild(REP_MEMBERS_LIST);
        assertFalse("the first overflow node must not exist", membersList.getChild("1").exists());

        // now add 10 users and check if the "1" node exists again
        toAdd = Sets.newHashSet();
        for (int i = 2 * SIZE_TH; i < (3 * SIZE_TH); i++) {
            memberIds.add(userIds[i]);
            toAdd.add(userIds[i]);
        }
        assertTrue(addMembers(grpTree, toAdd).isEmpty());
        assertMembers(grp, memberIds);

        membersList = grpTree.getChild(REP_MEMBERS_LIST);
        assertTrue("the first overflow node must not exist", membersList.getChild("1").exists());
    }

    Set<String> addMembers(@Nonnull Tree grpTree, @Nonnull Iterable<String> memberIds) throws Exception {
        Set<String> failed = Sets.newHashSet();
        for (String id : memberIds) {
            // insert one-by-one to generate a content structure that fills the
            // rep:members properties in the expected way (compared to passing in a map)
            if (!writer.addMember(grpTree, getContentID(id))) {
                failed.add(id);
            }
        }
        root.commit();
        return failed;
    }
}