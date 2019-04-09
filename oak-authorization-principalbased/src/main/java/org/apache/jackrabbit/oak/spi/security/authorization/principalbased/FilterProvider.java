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
package org.apache.jackrabbit.oak.spi.security.authorization.principalbased;

import org.apache.jackrabbit.oak.api.Root;
import org.apache.jackrabbit.oak.namepath.NamePathMapper;
import org.apache.jackrabbit.oak.spi.security.SecurityProvider;
import org.jetbrains.annotations.NotNull;
import org.osgi.annotation.versioning.ProviderType;

/**
 * Interface that allows to define the principals for which principal based access control management and permission
 * evaluation can be executed. For any other principals this module would never take effect.
 */
@ProviderType
public interface FilterProvider {

    /**
     *
     * @param absPath The absolute oak path to be tested.
     * @return
     */
    boolean handlesPath(@NotNull String oakPath);

    /**
     * TODO
     *
     * @return
     */
    String getFilterRoot();

    /**
     * TODO
     *
     * @param securityProvider
     * @param root
     * @param namePathMapper
     * @return
     */
    Filter getFilter(SecurityProvider securityProvider, Root root, @NotNull NamePathMapper namePathMapper);
}
