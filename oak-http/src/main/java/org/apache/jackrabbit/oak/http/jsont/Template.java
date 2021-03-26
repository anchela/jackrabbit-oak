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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;

import javax.jcr.PropertyType;

import com.fasterxml.jackson.core.JsonGenerator;

import org.apache.jackrabbit.oak.api.Blob;
import org.apache.jackrabbit.oak.api.PropertyState;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.api.Type;
import org.jetbrains.annotations.NotNull;

import static org.apache.jackrabbit.oak.api.Type.BINARIES;
import static org.apache.jackrabbit.oak.api.Type.BOOLEANS;
import static org.apache.jackrabbit.oak.api.Type.DECIMALS;
import static org.apache.jackrabbit.oak.api.Type.DOUBLES;
import static org.apache.jackrabbit.oak.api.Type.LONGS;
import static org.apache.jackrabbit.oak.api.Type.STRINGS;

public class Template {

    private final Tree templateTree;

    public Template(@NotNull Tree template) {
        this.templateTree = template;
    }

    /**
     * Verfiy if the given {@code Tree} matches the condition defined in the 'match' property of this template.
     * E.g.
     * <pre>
     *     match: "sling:resourceType == 'component/image'"
     * </pre>
     * will return {@code true}, if the given tree contains a property _sling:resourceType_ with the value _component/image_,
     * and false if no such property exists or if it has a different value.
     *
     * @param tree The target tree
     * @return true if this template matches the given {@code Tree}.
     */
    public boolean matches(@NotNull Tree tree) {
        PropertyState p = templateTree.getProperty("match");
        if (p == null) {
            return false;
        }
        String matchExpression = p.getValue(Type.STRING);
        int i = matchExpression.indexOf("==");
        if (i > 0) {
            String matchName = matchExpression.substring(0, i).trim();
            PropertyState matchProperty = tree.getProperty(matchName);
            return matchProperty != null && matchesProperty(matchExpression, i+2, matchProperty);
        } else {
            // malformatted match-expression. TODO: is format of template guaranteed to be valid?
            return false;
        }
    }

    private static boolean matchesProperty(@NotNull String matchExpression, int startIndex, @NotNull PropertyState matchProperty) {
        if (matchProperty.isArray()) {
            return false;
        }
        String v = matchExpression.substring(startIndex).trim();
        if (v.startsWith("'")) {
            v = v.substring(1, v.length()-1);
        }
        return v.equals(matchProperty.getValue(Type.STRING));
    }

    public void transform(Tree tree, JsonGenerator generator) {
        // TODO
    }

    private static void render(PropertyState property, JsonGenerator generator)
            throws IOException {
        if (property.isArray()) {
            generator.writeStartArray();
            renderValue(property, generator);
            generator.writeEndArray();
        } else {
            renderValue(property, generator);
        }
    }

    private static void renderValue(PropertyState property, JsonGenerator generator)
            throws IOException {
        // TODO: Type info?
        int type = property.getType().tag();
        if (type == PropertyType.BOOLEAN) {
            for (boolean value : property.getValue(BOOLEANS)) {
                generator.writeBoolean(value);
            }
        } else if (type == PropertyType.DECIMAL) {
            for (BigDecimal value : property.getValue(DECIMALS)) {
                generator.writeNumber(value);
            }
        } else if (type == PropertyType.DOUBLE) {
            for (double value : property.getValue(DOUBLES)) {
                generator.writeNumber(value);
            }
        } else if (type == PropertyType.LONG) {
            for (long value : property.getValue(LONGS)) {
                generator.writeNumber(value);
            }
        } else if (type == PropertyType.BINARY) {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            for (Blob value : property.getValue(BINARIES)) {
                InputStream stream = value.getNewStream();
                try {
                    byte[] b = new byte[1024];
                    int n = stream.read(b);
                    while (n != -1) {
                        buffer.write(b, 0, n);
                        n = stream.read(b);
                    }
                } finally {
                    stream.close();
                }
                generator.writeBinary(buffer.toByteArray());
            }
        } else {
            for (String value : property.getValue(STRINGS)) {
                generator.writeString(value);
            }
        }
    }
}
