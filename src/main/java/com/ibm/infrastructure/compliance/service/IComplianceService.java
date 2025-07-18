/*
 * CBOMkit
 * Copyright (C) 2025 IBM
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

import com.ibm.domain.compliance.CryptographicAsset;
import com.ibm.domain.compliance.PolicyIdentifier;
import com.ibm.infrastructure.compliance.AssessmentLevel;
import com.ibm.infrastructure.compliance.ComplianceLevel;
import jakarta.annotation.Nonnull;
import java.util.Collection;
import java.util.List;

public interface IComplianceService {

    @Nonnull
    String getName();

    @Nonnull
    List<ComplianceLevel> getComplianceLevels();

    @Nonnull
    ComplianceLevel getDefaultComplianceLevel();

    @Nonnull
    AssessmentLevel getDefaultAssessmentLevel();

    @Nonnull
    ComplianceCheckResultDTO evaluate(
            @Nonnull PolicyIdentifier policyIdentifier,
            @Nonnull Collection<CryptographicAsset> cryptographicAssets);
}
