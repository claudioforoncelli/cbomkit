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

import com.ibm.domain.compliance.*;
import com.ibm.infrastructure.compliance.*;
import com.ibm.infrastructure.compliance.service.custom.*;
import jakarta.annotation.Nonnull;
import java.util.*;
import java.util.stream.Collectors;
import org.cyclonedx.model.component.crypto.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CustomComplianceService implements IComplianceService {

    private static final Logger logger = LoggerFactory.getLogger(CustomComplianceService.class);

    private final CustomCompliancePolicy policy;
    private final Map<String, ComplianceLevel> levelMap;
    private final List<ComplianceLevel> levels;

    public CustomComplianceService(CustomCompliancePolicy policy) {
        this.policy = policy;
        this.levelMap =
                policy.getLevels().stream()
                        .collect(Collectors.toMap(l -> String.valueOf(l.id()), l -> l));
        this.levels = new ArrayList<>(levelMap.values());
    }

    @Nonnull
    @Override
    public String getName() {
        return policy.getName();
    }

    @Nonnull
    @Override
    public List<ComplianceLevel> getComplianceLevels() {
        return new ArrayList<>(levels);
    }

    @Nonnull
    @Override
    public ComplianceLevel getDefaultComplianceLevel() {
        return levelMap.getOrDefault(
                String.valueOf(policy.getDefaultLevel()),
                levels.stream()
                        .findFirst()
                        .orElseThrow(
                                () ->
                                        new IllegalStateException(
                                                "No default compliance level defined")));
    }

    @Nonnull
    @Override
    public ComplianceCheckResultDTO evaluate(
            @Nonnull PolicyIdentifier policyIdentifier,
            @Nonnull Collection<CryptographicAsset> assets) {

        List<ICryptographicAssetPolicyResult> results =
                assets.stream().map(this::evaluate).collect(Collectors.toList());

        return new ComplianceCheckResultDTO(results, false);
    }

    @Nonnull
    private ICryptographicAssetPolicyResult evaluate(@Nonnull CryptographicAsset asset) {
        var props = asset.component().getCryptoProperties();
        ComplianceLevel worstLevel = getDefaultComplianceLevel();
        StringBuilder combinedDescription = new StringBuilder();

        List<RuleDefinition> rules = policy.getRules();
        for (RuleDefinition rule : rules) {
            CryptoProperties ruleProps = rule.getCryptoProperties();
            if (!Objects.equals(ruleProps.getAssetType(), props.getAssetType())) continue;

            logger.debug("Evaluating rule: {}", rule.getDescription());

            String assetOid = props.getOid();
            String ruleOid = ruleProps.getOid();
            if (ruleOid != null && !matches(ruleOid, assetOid)) {
                logger.debug(" - field 'oid': expected={}, actual={} → ✗", ruleOid, assetOid);
                continue;
            } else if (ruleOid != null) {
                logger.debug(" - field 'oid': expected={}, actual={} → ✓", ruleOid, assetOid);
            }

            String assetName = asset.component().getName();
            String ruleName = rule.getName();
            if (ruleName != null && !matches(ruleName, assetName)) {
                logger.debug(" - field 'name': expected={}, actual={} → ✗", ruleName, assetName);
                continue;
            } else if (ruleName != null) {
                logger.debug(" - field 'name': expected={}, actual={} → ✓", ruleName, assetName);
            }

            boolean matched =
                    switch (props.getAssetType()) {
                        case ALGORITHM ->
                                matchAlgorithm(
                                        props.getAlgorithmProperties(),
                                        ruleProps.getAlgorithmProperties());
                        case CERTIFICATE ->
                                matchCertificate(
                                        props.getCertificateProperties(),
                                        ruleProps.getCertificateProperties());
                        case PROTOCOL ->
                                matchProtocol(
                                        props.getProtocolProperties(),
                                        ruleProps.getProtocolProperties());
                        case RELATED_CRYPTO_MATERIAL ->
                                matchRelatedMaterial(
                                        props.getRelatedCryptoMaterialProperties(),
                                        ruleProps.getRelatedCryptoMaterialProperties());
                        default -> false;
                    };

            if (matched) {
                logger.debug("Rule matched.");
                worstLevel =
                        updateWorstLevel(
                                worstLevel,
                                rule.getLevelId(),
                                rule.getDescription(),
                                combinedDescription);
            } else {
                logger.debug("Rule did not match.");
            }
        }

        if (combinedDescription.isEmpty()) {
            combinedDescription
                    .append("No compliance rules matched for asset type: ")
                    .append(props.getAssetType());
        }

        return new BasicCryptographicAssetPolicyResult(
                asset.identifier().toLowerCase(),
                worstLevel,
                combinedDescription.toString().trim());
    }

    private boolean matchAlgorithm(AlgorithmProperties actual, AlgorithmProperties rule) {
        if (rule == null || actual == null) return false;
        if (!fieldMatch("primitive", rule.getPrimitive(), actual.getPrimitive())) return false;
        if (!fieldMatch(
                "parameterSetIdentifier",
                rule.getParameterSetIdentifier(),
                actual.getParameterSetIdentifier())) return false;
        if (!fieldMatch("curve", rule.getCurve(), actual.getCurve())) return false;
        if (!fieldMatch(
                "executionEnvironment",
                rule.getExecutionEnvironment(),
                actual.getExecutionEnvironment())) return false;
        if (!fieldMatch(
                "implementationPlatform",
                rule.getImplementationPlatform(),
                actual.getImplementationPlatform())) return false;
        if (!fieldMatch("mode", rule.getMode(), actual.getMode())) return false;
        if (!fieldMatch("padding", rule.getPadding(), actual.getPadding())) return false;
        if (!fieldMatch(
                "classicalSecurityLevel",
                rule.getClassicalSecurityLevel(),
                actual.getClassicalSecurityLevel())) return false;
        if (!fieldMatch(
                "nistQuantumSecurityLevel",
                rule.getNistQuantumSecurityLevel(),
                actual.getNistQuantumSecurityLevel())) return false;
        if (!fieldMatch(
                "certificationLevel", rule.getCertificationLevel(), actual.getCertificationLevel()))
            return false;
        if (!fieldMatch("cryptoFunctions", rule.getCryptoFunctions(), actual.getCryptoFunctions()))
            return false;
        return true;
    }

    private boolean matchCertificate(CertificateProperties actual, CertificateProperties rule) {
        if (rule == null || actual == null) return false;
        if (!fieldMatch("subjectName", rule.getSubjectName(), actual.getSubjectName()))
            return false;
        if (!fieldMatch("issuerName", rule.getIssuerName(), actual.getIssuerName())) return false;
        if (!fieldMatch("notValidBefore", rule.getNotValidBefore(), actual.getNotValidBefore()))
            return false;
        if (!fieldMatch("notValidAfter", rule.getNotValidAfter(), actual.getNotValidAfter()))
            return false;
        if (!fieldMatch(
                "signatureAlgorithmRef",
                rule.getSignatureAlgorithmRef(),
                actual.getSignatureAlgorithmRef())) return false;
        if (!fieldMatch(
                "subjectPublicKeyRef",
                rule.getSubjectPublicKeyRef(),
                actual.getSubjectPublicKeyRef())) return false;
        if (!fieldMatch(
                "certificateFormat", rule.getCertificateFormat(), actual.getCertificateFormat()))
            return false;
        if (!fieldMatch(
                "certificateExtension",
                rule.getCertificateExtension(),
                actual.getCertificateExtension())) return false;
        return true;
    }

    private boolean matchProtocol(ProtocolProperties actual, ProtocolProperties rule) {
        if (rule == null || actual == null) return false;
        boolean result = true;
        result &= fieldMatch("type", rule.getType(), actual.getType());
        result &= fieldMatch("version", rule.getVersion(), actual.getVersion());
        if (rule.getCipherSuites() != null) {
            boolean suiteMatch =
                    actual.getCipherSuites() != null
                            && actual.getCipherSuites().stream()
                                    .anyMatch(
                                            protoSuite ->
                                                    rule.getCipherSuites().stream()
                                                            .anyMatch(
                                                                    ruleSuite ->
                                                                            ruleSuite
                                                                                    .getName()
                                                                                    .equalsIgnoreCase(
                                                                                            protoSuite
                                                                                                    .getName())));
            logger.debug(" - field 'cipherSuites': expected contains ≈ actual? {}", suiteMatch);
            result &= suiteMatch;
        }
        return result;
    }

    private boolean matchRelatedMaterial(
            RelatedCryptoMaterialProperties actual, RelatedCryptoMaterialProperties rule) {
        if (rule == null || actual == null) return false;
        if (!fieldMatch("type", rule.getType(), actual.getType())) return false;
        if (!fieldMatch("id", rule.getId(), actual.getId())) return false;
        if (!fieldMatch("state", rule.getState(), actual.getState())) return false;
        if (!fieldMatch("algorithmRef", rule.getAlgorithmRef(), actual.getAlgorithmRef()))
            return false;
        if (!fieldMatch("creationDate", rule.getCreationDate(), actual.getCreationDate()))
            return false;
        if (!fieldMatch("activationDate", rule.getActivationDate(), actual.getActivationDate()))
            return false;
        if (!fieldMatch("updateDate", rule.getUpdateDate(), actual.getUpdateDate())) return false;
        if (!fieldMatch("expirationDate", rule.getExpirationDate(), actual.getExpirationDate()))
            return false;
        if (!fieldMatch("value", rule.getValue(), actual.getValue())) return false;
        if (!fieldMatch("size", rule.getSize(), actual.getSize())) return false;
        if (!fieldMatch("format", rule.getFormat(), actual.getFormat())) return false;
        return true;
    }

    private boolean fieldMatch(String field, Object ruleValue, Object actualValue) {
        boolean match = matches(ruleValue, actualValue);
        logger.debug(
                " - field '{}': expected={}, actual={} → {}",
                field,
                Objects.toString(ruleValue, "null"),
                Objects.toString(actualValue, "null"),
                match ? "✓" : "✗");
        return match;
    }

    private ComplianceLevel updateWorstLevel(
            ComplianceLevel currentLevel,
            int newLevelId,
            String description,
            StringBuilder descriptionBuilder) {
        ComplianceLevel level =
                levelMap.getOrDefault(String.valueOf(newLevelId), getDefaultComplianceLevel());
        if (level.id() > currentLevel.id()) {
            currentLevel = level;
        }
        descriptionBuilder.append("- ").append(description).append("\n");
        return currentLevel;
    }

    private boolean matches(Object ruleValue, Object actualValue) {
        if (ruleValue == null) return true;
        if (actualValue == null) return false;

        if (ruleValue instanceof String ruleStr && actualValue instanceof String actualStr) {
            return ruleStr.trim().equalsIgnoreCase(actualStr.trim());
        }
        if (ruleValue instanceof Enum<?> ruleEnum && actualValue instanceof Enum<?> actualEnum) {
            return ruleEnum.name().equalsIgnoreCase(actualEnum.name());
        }
        if (ruleValue instanceof Integer ruleInt && actualValue instanceof Integer actualInt) {
            return ruleInt.equals(actualInt);
        }
        if (ruleValue instanceof Number ruleNum && actualValue instanceof Number actualNum) {
            return ruleNum.intValue() == actualNum.intValue();
        }
        return ruleValue.toString().trim().equalsIgnoreCase(actualValue.toString().trim());
    }
}
