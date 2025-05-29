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
package com.ibm.infrastructure.compliance.service.custom;

import com.ibm.infrastructure.compliance.ComplianceLevel;
import com.ibm.infrastructure.compliance.service.custom.rules.*;
import java.util.List;

public class CustomCompliancePolicy {
    private String id;
    private String name;
    private int defaultLevel;
    private List<ComplianceLevel> levels;

    private List<AlgorithmRuleDefinition> algorithmRules;
    private List<CertificateRuleDefinition> certificateRules;
    private List<RelatedCryptoMaterialRules> relatedCryptoMaterialRules;
    private List<ProtocolRuleDefinition> protocolRules;

    private List<RuleDefinition> hashAlgorithms;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getDefaultLevel() {
        return defaultLevel;
    }

    public void setDefaultLevel(int defaultLevel) {
        this.defaultLevel = defaultLevel;
    }

    public List<ComplianceLevel> getLevels() {
        return levels;
    }

    public void setLevels(List<ComplianceLevel> levels) {
        this.levels = levels;
    }

    public List<RuleDefinition> getHashAlgorithms() {
        return hashAlgorithms;
    }

    public void setHashAlgorithms(List<RuleDefinition> hashAlgorithms) {
        this.hashAlgorithms = hashAlgorithms;
    }

    public List<AlgorithmRuleDefinition> getAlgorithmRules() {
        return algorithmRules;
    }

    public void setAlgorithmRules(List<AlgorithmRuleDefinition> algorithmRules) {
        this.algorithmRules = algorithmRules;
    }

    public List<CertificateRuleDefinition> getCertificateRules() {
        return certificateRules;
    }

    public void setCertificateRules(List<CertificateRuleDefinition> certificateRules) {
        this.certificateRules = certificateRules;
    }

    public List<RelatedCryptoMaterialRules> getRelatedCryptoMaterialRules() {
        return relatedCryptoMaterialRules;
    }

    public void setRelatedCryptoMaterialRules(
            List<RelatedCryptoMaterialRules> relatedCryptoMaterialRules) {
        this.relatedCryptoMaterialRules = relatedCryptoMaterialRules;
    }

    public List<ProtocolRuleDefinition> getProtocolRules() {
        return protocolRules;
    }

    public void setProtocolRules(List<ProtocolRuleDefinition> protocolRules) {
        this.protocolRules = protocolRules;
    }
}
