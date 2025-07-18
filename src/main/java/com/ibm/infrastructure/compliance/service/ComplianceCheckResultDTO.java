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
package com.ibm.infrastructure.compliance.service;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.ibm.infrastructure.compliance.AssessmentLevel;
import jakarta.annotation.Nonnull;
import java.util.Collection;

public class ComplianceCheckResultDTO {

    @Nonnull private final Collection<ICryptographicAssetPolicyResult> policyResults;

    private final boolean error;

    private final AssessmentLevel assessmentLevel;

    public ComplianceCheckResultDTO(
            @Nonnull Collection<ICryptographicAssetPolicyResult> policyResults,
            boolean error,
            AssessmentLevel assessmentLevel) {
        this.policyResults = policyResults;
        this.error = error;
        this.assessmentLevel = assessmentLevel;
    }

    @JsonProperty("findings")
    public Collection<ICryptographicAssetPolicyResult> getPolicyResults() {
        return policyResults;
    }

    public boolean isError() {
        return error;
    }

    @JsonProperty("assessmentLevel")
    public AssessmentLevel getAssessmentLevel() {
        return assessmentLevel;
    }
}
