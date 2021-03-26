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

import java.io.IOException;

import javax.servlet.http.HttpServletResponse;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;

import org.apache.jackrabbit.oak.api.PropertyState;
import org.apache.jackrabbit.oak.api.Tree;
import org.apache.jackrabbit.oak.http.Representation;
import org.apache.tika.mime.MediaType;

/**
 * Renders JSON using templates.
 */
public class JsonTemplateRepresentation implements Representation {

    private final MediaType type;

    private final JsonFactory factory;

    public JsonTemplateRepresentation(MediaType type, JsonFactory factory) {
        this.type = type;
        this.factory = factory;
    }

    @Override
    public MediaType getType() {
        return type;
    }

    @Override
    public void render(Tree tree, HttpServletResponse response)
            throws IOException {
        TemplateRegistry registry = createTemplateRegistry(tree);
        JsonGenerator generator = startResponse(response);
        render(tree, generator, registry);
        generator.close();
    }

    @Override
    public void render(PropertyState property, HttpServletResponse response)
            throws IOException {
        throw new UnsupportedOperationException();
    }

    protected JsonGenerator startResponse(HttpServletResponse response)
            throws IOException {
        response.setContentType(type.toString());
        return factory.createGenerator(response.getOutputStream());
    }

    private static TemplateRegistry createTemplateRegistry(Tree tree) {
        Tree t = tree;
        while (!t.isRoot()) {
            t = t.getParent();
        }
        return new TemplateRegistry(t.getChild("templates"));
    }

    private static void render(Tree tree,
                               JsonGenerator generator,
                               TemplateRegistry registry)
            throws IOException {
        registry.findMatch(tree).ifPresent(template -> template.transform(tree, generator));
    }

}
