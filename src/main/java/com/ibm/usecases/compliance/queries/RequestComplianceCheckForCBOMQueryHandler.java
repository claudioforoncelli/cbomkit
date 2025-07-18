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
package com.ibm.usecases.compliance.queries;

import app.bootstrap.core.cqrs.IQueryBus;
import app.bootstrap.core.cqrs.QueryHandler;
import com.ibm.domain.compliance.CryptographicAsset;
import com.ibm.domain.compliance.PolicyIdentifier;
import com.ibm.infrastructure.compliance.*;
import com.ibm.infrastructure.compliance.service.ComplianceCheckResultDTO;
import com.ibm.infrastructure.compliance.service.IComplianceService;
import com.ibm.usecases.compliance.service.CompliancePreparationService;
import io.quarkus.runtime.StartupEvent;
import jakarta.annotation.Nonnull;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Singleton;
import java.util.Collection;

@Singleton
public final class RequestComplianceCheckForCBOMQueryHandler
        extends QueryHandler<RequestComplianceCheckForCBOMQuery, ComplianceResult> {
    @Nonnull private final ComplianceServiceSelector complianceSelector;

    void onStart(@Observes StartupEvent event) {
        this.queryBus.register(this, RequestComplianceCheckForCBOMQuery.class);
    }

    public RequestComplianceCheckForCBOMQueryHandler(
            @Nonnull IQueryBus queryBus, @Nonnull ComplianceServiceSelector complianceSelector) {
        super(queryBus);
        this.complianceSelector = complianceSelector;
    }

    @Override
    public @Nonnull ComplianceResult handle(
            @Nonnull RequestComplianceCheckForCBOMQuery requestComplianceCheckForCBOMQuery)
            throws Exception {

        final CompliancePreparationService compliancePreparationService =
                new CompliancePreparationService();
        final Collection<CryptographicAsset> cryptographicAssets =
                compliancePreparationService.transformCBOMString(
                        requestComplianceCheckForCBOMQuery.cbom());

        final PolicyIdentifier policyIdentifier =
                new PolicyIdentifier(requestComplianceCheckForCBOMQuery.policyIdentifier());

        final IComplianceService selectedComplianceService =
                this.complianceSelector.getService(policyIdentifier.id());

        final ComplianceCheckResultDTO complianceCheckResultDTO =
                selectedComplianceService.evaluate(policyIdentifier, cryptographicAssets);

        if (complianceCheckResultDTO.isError()) {
            return ComplianceResult.error(selectedComplianceService.getName());
        }

        return new ComplianceResult(
                selectedComplianceService.getName(),
                policyIdentifier.id(),
                complianceCheckResultDTO.getPolicyResults().stream()
                        .map(
                                result ->
                                        new ComplianceFinding(
                                                result.identifier(),
                                                result.complianceLevel().id(),
                                                result.message()))
                        .toList(),
                selectedComplianceService.getComplianceLevels(),
                selectedComplianceService.getDefaultComplianceLevel().id(),
                selectedComplianceService.getDefaultAssessmentLevel(),
                complianceCheckResultDTO.getAssessmentLevel(),
                false);
    }
}
