/*
 * CBOMkit
 * Copyright (C) 2024 IBM
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.ibm.infrastructure.compliance;

import com.fasterxml.jackson.annotation.JsonInclude;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ComplianceLevel(
        int id,
        @Nonnull String label,
        @Nullable String description,
        @Nonnull String colorHex,
        @Nonnull ComplianceIcon icon,
        int assessmentId) {

    public enum ComplianceIcon {
        CHECKMARK,
        CHECKMARK_SECURE,
        WARNING,
        ERROR,
        NOT_APPLICABLE,
        UNKNOWN,
        TEST,
    }

    public static final ComplianceLevel UNKNOWN =
            new ComplianceLevel(
                    0,
                    "unknown",
                    null,
                    null,
                    ComplianceIcon.UNKNOWN,
                    AssessmentLevel.UNKNOWN.getId());
}
