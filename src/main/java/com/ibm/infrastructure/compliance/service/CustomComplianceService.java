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
import com.ibm.infrastructure.compliance.service.custom.rules.*;
import jakarta.annotation.Nonnull;
import java.util.*;
import java.util.stream.Collectors;

public class CustomComplianceService implements IComplianceService {

    private final CustomCompliancePolicy policy;
    private final Map<String, ComplianceLevel> levelMap;

    public CustomComplianceService(CustomCompliancePolicy policy) {
        this.policy = policy;
        this.levelMap =
                policy.getLevels().stream()
                        .collect(Collectors.toMap(l -> String.valueOf(l.id()), l -> l));
    }

    @Nonnull
    @Override
    public String getName() {
        return policy.getName();
    }

    @Nonnull
    @Override
    public List<ComplianceLevel> getComplianceLevels() {
        return new ArrayList<>(levelMap.values());
    }

    @Nonnull
    @Override
    public ComplianceLevel getDefaultComplianceLevel() {
        return levelMap.getOrDefault(
                String.valueOf(policy.getDefaultLevel()),
                getComplianceLevels().stream()
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

        ComplianceCheckResultDTO resultDTO = new ComplianceCheckResultDTO(results, false);

        System.out.println("==== Final Compliance Results ====");
        for (ICryptographicAssetPolicyResult result : resultDTO.policyResults()) {
            System.out.println("Asset ID: " + result.identifier());
            System.out.println("  Compliance Level: " + result.complianceLevel().label());
            System.out.println("  Description:\n" + result.message());
        }
        System.out.println("==================================");

        return resultDTO;
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

    @Nonnull
    private ICryptographicAssetPolicyResult evaluate(@Nonnull CryptographicAsset asset) {
        var props = asset.component().getCryptoProperties();
        ComplianceLevel worstLevel = getDefaultComplianceLevel();
        StringBuilder combinedDescription = new StringBuilder();

        System.out.println("Evaluating asset: " + asset.identifier());

        switch (props.getAssetType()) {
            case ALGORITHM -> {
                var alg = props.getAlgorithmProperties();
                System.out.println("Evaluating ALGORITHM:");
                System.out.println("Primitive: " + alg.getPrimitive());
                System.out.println("ParameterSetIdentifier: " + alg.getParameterSetIdentifier());
                System.out.println("Curve: " + alg.getCurve());
                System.out.println("ExecutionEnvironment: " + alg.getExecutionEnvironment());
                System.out.println("ImplementationPlatform: " + alg.getImplementationPlatform());
                System.out.println("Mode: " + alg.getMode());
                System.out.println("Padding: " + alg.getPadding());
                System.out.println("ClassicalSecurityLevel: " + alg.getClassicalSecurityLevel());
                System.out.println(
                        "NistQuantumSecurityLevel: " + alg.getNistQuantumSecurityLevel());

                for (AlgorithmRuleDefinition rule : policy.getAlgorithmRules()) {
                    Boolean[] matches =
                            new Boolean[] {
                                matches(rule.getPrimitive(), String.valueOf(alg.getPrimitive())),
                                matches(
                                        rule.getParameterSetIdentifier(),
                                        alg.getParameterSetIdentifier()),
                                matches(rule.getCurve(), alg.getCurve()),
                                matches(
                                        rule.getExecutionEnvironment(),
                                        String.valueOf(alg.getExecutionEnvironment())),
                                matches(
                                        rule.getImplementationPlatform(),
                                        String.valueOf(alg.getImplementationPlatform())),
                                matches(rule.getMode(), String.valueOf(alg.getMode())),
                                matches(rule.getPadding(), String.valueOf(alg.getPadding())),
                                matches(
                                        rule.getClassicalSecurityLevel(),
                                        alg.getClassicalSecurityLevel()),
                                matches(
                                        rule.getNistQuantumSecurityLevel(),
                                        alg.getNistQuantumSecurityLevel())
                            };

                    if (Arrays.asList(matches).stream().allMatch(Boolean::booleanValue)) {
                        boolean certLevelMatch =
                                rule.getCertificationLevel() == null
                                        || (alg.getCertificationLevel() != null
                                                && alg.getCertificationLevel().stream()
                                                        .anyMatch(
                                                                val ->
                                                                        rule
                                                                                .getCertificationLevel()
                                                                                .stream()
                                                                                .anyMatch(
                                                                                        r ->
                                                                                                r
                                                                                                        .equalsIgnoreCase(
                                                                                                                String
                                                                                                                        .valueOf(
                                                                                                                                val)))));

                        boolean cryptoFuncMatch =
                                rule.getCryptoFunctions() == null
                                        || (alg.getCryptoFunctions() != null
                                                && alg.getCryptoFunctions().stream()
                                                        .anyMatch(
                                                                val ->
                                                                        rule
                                                                                .getCryptoFunctions()
                                                                                .stream()
                                                                                .anyMatch(
                                                                                        r ->
                                                                                                r
                                                                                                        .equalsIgnoreCase(
                                                                                                                String
                                                                                                                        .valueOf(
                                                                                                                                val)))));

                        if (certLevelMatch && cryptoFuncMatch) {
                            System.out.println(
                                    "Matched algorithm rule: "
                                            + rule.getDescription()
                                            + ", Level ID: "
                                            + rule.getLevelId());
                            worstLevel =
                                    updateWorstLevel(
                                            worstLevel,
                                            rule.getLevelId(),
                                            rule.getDescription(),
                                            combinedDescription);
                        }
                    }
                }
            }

            case CERTIFICATE -> {
                var cert = props.getCertificateProperties();
                System.out.println("Evaluating CERTIFICATE:");
                System.out.println("SubjectName: " + cert.getSubjectName());
                System.out.println("IssuerName: " + cert.getIssuerName());
                System.out.println("NotValidBefore: " + cert.getNotValidBefore());
                System.out.println("NotValidAfter: " + cert.getNotValidAfter());
                System.out.println("SignatureAlgorithmRef: " + cert.getSignatureAlgorithmRef());
                System.out.println("SubjectPublicKeyRef: " + cert.getSubjectPublicKeyRef());
                System.out.println("CertificateFormat: " + cert.getCertificateFormat());
                System.out.println("CertificateExtension: " + cert.getCertificateExtension());

                for (CertificateRuleDefinition rule : policy.getCertificateRules()) {
                    Boolean[] matches =
                            new Boolean[] {
                                matches(rule.getSubjectName(), cert.getSubjectName()),
                                matches(rule.getIssuerName(), cert.getIssuerName()),
                                matches(rule.getNotValidBefore(), cert.getNotValidBefore()),
                                matches(rule.getNotValidAfter(), cert.getNotValidAfter()),
                                matches(
                                        rule.getSignatureAlgorithmRef(),
                                        cert.getSignatureAlgorithmRef()),
                                matches(
                                        rule.getSubjectPublicKeyRef(),
                                        cert.getSubjectPublicKeyRef()),
                                matches(rule.getCertificateFormat(), cert.getCertificateFormat()),
                                matches(
                                        rule.getCertificateExtension(),
                                        cert.getCertificateExtension())
                            };

                    if (Arrays.asList(matches).stream().allMatch(Boolean::booleanValue)) {
                        System.out.println("Matched certificate rule: " + rule.getDescription());
                        worstLevel =
                                updateWorstLevel(
                                        worstLevel,
                                        rule.getLevelId(),
                                        rule.getDescription(),
                                        combinedDescription);
                    }
                }
            }

            case PROTOCOL -> {
                var proto = props.getProtocolProperties();
                System.out.println("Evaluating PROTOCOL:");
                System.out.println("Type: " + proto.getType());
                System.out.println("Version: " + proto.getVersion());

                for (ProtocolRuleDefinition rule : policy.getProtocolRules()) {
                    Boolean[] matches =
                            new Boolean[] {
                                matches(rule.getType(), proto.getType()),
                                matches(rule.getVersion(), proto.getVersion())
                            };

                    boolean cipherMatch =
                            rule.getCipherSuites() == null
                                    || (proto.getCipherSuites() != null
                                            && proto.getCipherSuites().stream()
                                                    .anyMatch(
                                                            protoSuite ->
                                                                    rule.getCipherSuites().stream()
                                                                            .anyMatch(
                                                                                    ruleSuite ->
                                                                                            ruleSuite
                                                                                                    .getName()
                                                                                                    .equalsIgnoreCase(
                                                                                                            protoSuite
                                                                                                                    .getName()))));

                    boolean ikeMatch = true;
                    if (rule.getIkev2TransformTypes() != null
                            && proto.getIkev2TransformTypes() != null) {
                        ikeMatch =
                                rule.getIkev2TransformTypes().entrySet().stream()
                                        .allMatch(
                                                e -> {
                                                    var protoRef =
                                                            proto.getIkev2TransformTypes()
                                                                    .get(e.getKey());
                                                    return protoRef != null
                                                            && protoRef.getRef() != null
                                                            && new HashSet<>(protoRef.getRef())
                                                                    .containsAll(
                                                                            e.getValue().getRef());
                                                });
                    }

                    if (Arrays.asList(matches).stream().allMatch(Boolean::booleanValue)
                            && cipherMatch
                            && ikeMatch) {
                        System.out.println("Matched protocol rule: " + rule.getDescription());
                        worstLevel =
                                updateWorstLevel(
                                        worstLevel,
                                        rule.getLevelId(),
                                        rule.getDescription(),
                                        combinedDescription);
                    }
                }
            }

            case RELATED_CRYPTO_MATERIAL -> {
                var mat = props.getRelatedCryptoMaterialProperties();
                System.out.println("Evaluating RELATED_CRYPTO_MATERIAL:");
                System.out.println("Type: " + mat.getType());
                System.out.println("Id: " + mat.getId());
                System.out.println("State: " + mat.getState());
                System.out.println("AlgorithmRef: " + mat.getAlgorithmRef());
                System.out.println("CreationDate: " + mat.getCreationDate());
                System.out.println("ActivationDate: " + mat.getActivationDate());
                System.out.println("UpdateDate: " + mat.getUpdateDate());
                System.out.println("ExpirationDate: " + mat.getExpirationDate());
                System.out.println("Value: " + mat.getValue());
                System.out.println("Size: " + mat.getSize());
                System.out.println("Format: " + mat.getFormat());

                for (RelatedCryptoMaterialRules rule : policy.getRelatedCryptoMaterialRules()) {
                    Boolean[] matches =
                            new Boolean[] {
                                matches(rule.getType(), mat.getType()),
                                matches(rule.getId(), mat.getId()),
                                matches(rule.getState(), mat.getState()),
                                matches(rule.getAlgorithmRef(), mat.getAlgorithmRef()),
                                matches(rule.getCreationDate(), mat.getCreationDate()),
                                matches(rule.getActivationDate(), mat.getActivationDate()),
                                matches(rule.getUpdateDate(), mat.getUpdateDate()),
                                matches(rule.getExpirationDate(), mat.getExpirationDate()),
                                matches(rule.getValue(), mat.getValue()),
                                matches(rule.getSize(), mat.getSize()),
                                matches(rule.getFormat(), mat.getFormat())
                            };

                    if (Arrays.asList(matches).stream().allMatch(Boolean::booleanValue)) {
                        System.out.println(
                                "Matched crypto material rule: " + rule.getDescription());
                        worstLevel =
                                updateWorstLevel(
                                        worstLevel,
                                        rule.getLevelId(),
                                        rule.getDescription(),
                                        combinedDescription);
                    }
                }
            }

            default -> {
                System.out.println(
                        "No compliance rules implemented for asset type: " + props.getAssetType());
                combinedDescription
                        .append("No compliance rules implemented for asset type: ")
                        .append(props.getAssetType());
            }
        }

        if (combinedDescription.isEmpty()) {
            System.out.println("No compliance rules matched for asset: " + asset.identifier());
            combinedDescription
                    .append("No compliance rules matched for asset type: ")
                    .append(props.getAssetType());
        } else {
            System.out.println(
                    "Asset " + asset.identifier() + " evaluated with level " + worstLevel.id());
        }

        return new BasicCryptographicAssetPolicyResult(
                asset.identifier().toLowerCase(),
                worstLevel,
                combinedDescription.toString().trim());
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
}
