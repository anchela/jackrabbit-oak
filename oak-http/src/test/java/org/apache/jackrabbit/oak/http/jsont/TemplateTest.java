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
package org.apache.jackrabbit.oak.http.jsont;

import org.apache.jackrabbit.oak.api.PropertyState;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.plugins.memory.PropertyStates;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class TemplateTest {

    private final Tree templateTree = mock(Tree.class);
    private final Tree tree = mock(Tree.class);

    private final Template template = new Template(templateTree);

    @Test
    public void testMissingMatch() {
        assertFalse(template.matches(tree));
    }

    @Test
    public void testMatch() {
        PropertyState match = PropertyStates.createProperty("match", "sling:resourceType == 'component/image'");
        when(templateTree.getProperty("match")).thenReturn(match);

        assertFalse(template.matches(tree));

        PropertyState resourceType = PropertyStates.createProperty("sling:resourceType", "component/image");
        when(tree.getProperty("sling:resourceType")).thenReturn(resourceType);

        assertTrue(template.matches(tree));

        PropertyState resourceType2 = PropertyStates.createProperty("sling:resourceType", "component/txt");
        when(tree.getProperty("sling:resourceType")).thenReturn(resourceType2);

        assertFalse(template.matches(tree));
    }
}