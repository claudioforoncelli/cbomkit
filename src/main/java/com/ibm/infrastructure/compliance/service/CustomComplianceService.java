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
import com.ibm.infrastructure.compliance.ComplianceLevel;
import com.ibm.infrastructure.compliance.service.custom.CustomCompliancePolicy;
import com.ibm.infrastructure.compliance.service.custom.RuleDefinition;
import java.util.*;
import java.util.stream.Collectors;

public class CustomComplianceService implements IComplianceService {

    private final CustomCompliancePolicy policy;
    private final Map<String, ComplianceLevel> levelMap;

    public CustomComplianceService(CustomCompliancePolicy policy) {
        this.policy = policy;
        this.levelMap =
                policy.levels.stream().collect(Collectors.toMap(ComplianceLevel::label, l -> l));
    }

    @Override
    public String getName() {
        return policy.name;
    }

    @Override
    public List<ComplianceLevel> getComplianceLevels() {
        return new ArrayList<>(levelMap.values());
    }

    @Override
    public ComplianceLevel getDefaultComplianceLevel() {
        return levelMap.getOrDefault(
                policy.defaultLevel,
                getComplianceLevels().stream()
                        .findFirst()
                        .orElseThrow(
                                () ->
                                        new IllegalStateException(
                                                "No default compliance level defined")));
    }

    @Override
    public ComplianceCheckResultDTO evaluate(
            PolicyIdentifier policyIdentifier, Collection<CryptographicAsset> assets) {
        List<ICryptographicAssetPolicyResult> results = new ArrayList<>();
        for (CryptographicAsset asset : assets) {
            RuleDefinition rule = findRule(asset);
            ComplianceLevel level =
                    rule != null
                            ? levelMap.getOrDefault(rule.level, getDefaultComplianceLevel())
                            : getDefaultComplianceLevel();
            String description = rule != null ? rule.description : "Default policy level applied";
            results.add(
                    new BasicCryptographicAssetPolicyResult(
                            asset.identifier().toLowerCase(), level, description));
        }
        return new ComplianceCheckResultDTO(results, false);
    }

    private RuleDefinition findRule(CryptographicAsset asset) {
        return findRuleByName(
                asset.component().getName(),
                policy.primitives,
                policy.modes,
                policy.signatures,
                policy.cipherSuites,
                policy.contexts);
    }

    @SafeVarargs
    private final RuleDefinition findRuleByName(String name, List<RuleDefinition>... categories) {
        for (List<RuleDefinition> category : categories) {
            if (category != null) {
                Optional<RuleDefinition> match =
                        category.stream().filter(r -> r.name.equalsIgnoreCase(name)).findFirst();
                if (match.isPresent()) return match.get();
            }
        }
        return null;
    }
}
