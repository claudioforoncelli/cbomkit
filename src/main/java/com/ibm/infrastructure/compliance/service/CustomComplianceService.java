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
    public AssessmentLevel getDefaultAssessmentLevel() {
        return AssessmentLevel.UNKNOWN;
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

        List<ICryptographicAssetPolicyResult> results = new ArrayList<>();
        AssessmentLevel worstAssessment = getDefaultAssessmentLevel();

        logger.info(
                "Starting evaluation of {} assets for policy '{}'",
                assets.size(),
                policyIdentifier.id());

        for (CryptographicAsset asset : assets) {
            ICryptographicAssetPolicyResult result = evaluate(asset);
            results.add(result);

            ComplianceLevel level = result.complianceLevel();
            logger.info(
                    "Asset '{}' evaluated with compliance level '{}'",
                    result.identifier(),
                    level.label());

            AssessmentLevel assessmentLevel =
                    policy.getAssessmentLevels().stream()
                            .filter(s -> s.getId() == level.assessmentId())
                            .findFirst()
                            .orElse(null);

            if (assessmentLevel == null) {
                logger.warn(
                        "→ No severity level found for compliance level '{}' (assessmentId: {}). Using default severity '{}'",
                        level.label(),
                        level.assessmentId(),
                        getDefaultAssessmentLevel().getLabel());
            } else {
                logger.info("→ Mapped to severity: '{}'", assessmentLevel.getLabel());
                if (assessmentLevel.getId() > worstAssessment.getId()) {
                    worstAssessment = assessmentLevel;
                }
            }
        }

        logger.info("Final worst severity level determined: '{}'", worstAssessment.getLabel());
        return new ComplianceCheckResultDTO(results, false, worstAssessment);
    }

    @Nonnull
    private ICryptographicAssetPolicyResult evaluate(@Nonnull CryptographicAsset asset) {
        var props = asset.component().getCryptoProperties();

        int highestSpecificity = -1;
        ComplianceLevel bestLevel = getDefaultComplianceLevel();
        StringBuilder combinedDescription = new StringBuilder();
        String bestDescription = null;

        List<RuleDefinition> rules = policy.getRules();
        for (RuleDefinition rule : rules) {
            CryptoProperties ruleProps = rule.getCryptoProperties();
            if (!Objects.equals(ruleProps.getAssetType(), props.getAssetType())) continue;

            logger.debug("Evaluating rule: {}", rule.getDescription());

            String assetOid = props.getOid();
            String ruleOid = ruleProps.getOid();
            if (ruleOid != null && !matches(ruleOid, assetOid)) continue;

            String assetName = asset.component().getName();
            String ruleName = rule.getName();
            if (ruleName != null && !matches(ruleName, assetName)) continue;

            boolean matched =
                    switch (props.getAssetType()) {
                        case ALGORITHM ->
                                matchAlgorithm(
                                        props.getAlgorithmProperties(),
                                        ruleProps.getAlgorithmProperties(),
                                        rule);
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
                                        ruleProps.getRelatedCryptoMaterialProperties(),
                                        rule);
                        default -> false;
                    };

            if (matched) {
                int specificity = computeSpecificity(rule);
                ComplianceLevel level =
                        levelMap.getOrDefault(
                                String.valueOf(rule.getLevelId()), getDefaultComplianceLevel());

                if (specificity > highestSpecificity
                        || (specificity == highestSpecificity && level.id() > bestLevel.id())) {
                    highestSpecificity = specificity;
                    bestLevel = level;
                    bestDescription = rule.getDescription();
                }
            }
        }

        if (bestDescription != null) combinedDescription.append("- ").append(bestDescription);
        else
            combinedDescription
                    .append("No compliance rules matched for asset type: ")
                    .append(props.getAssetType());

        return new BasicCryptographicAssetPolicyResult(
                asset.identifier().toLowerCase(), bestLevel, combinedDescription.toString().trim());
    }

    // ---------- fieldMatch and matches (supports >=, <=, ranges) ----------

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

    private boolean matches(Object ruleValue, Object actualValue) {
        if (ruleValue == null) return true;
        if (actualValue == null) return false;

        // ---- Numeric or range-based string expressions ----
        if (ruleValue instanceof String ruleStr) {
            String rule = ruleStr.trim();
            String actualStr = actualValue.toString().trim();

            // Handle range expressions like ">=128 <512"
            if (rule.matches(".*[<>]=?.*\\d+.*")) {
                try {
                    double actualNum = Double.parseDouble(actualStr.replaceAll("[^0-9.]", ""));
                    boolean match = true;

                    for (String part : rule.split("\\s+")) {
                        part = part.trim();
                        if (part.matches(">=\\d+(\\.\\d+)?")) {
                            double min = Double.parseDouble(part.substring(2));
                            if (actualNum < min) match = false;
                        } else if (part.matches("<=\\d+(\\.\\d+)?")) {
                            double max = Double.parseDouble(part.substring(2));
                            if (actualNum > max) match = false;
                        } else if (part.matches(">\\d+(\\.\\d+)?")) {
                            double min = Double.parseDouble(part.substring(1));
                            if (actualNum <= min) match = false;
                        } else if (part.matches("<\\d+(\\.\\d+)?")) {
                            double max = Double.parseDouble(part.substring(1));
                            if (actualNum >= max) match = false;
                        } else if (part.matches("\\d+(\\.\\d+)?")) {
                            double exact = Double.parseDouble(part);
                            if (actualNum != exact) match = false;
                        }
                    }
                    return match;
                } catch (NumberFormatException e) {
                    // fallback to normal string match
                }
            }
            return rule.equalsIgnoreCase(actualStr);
        }

        // ---- Enums ----
        if (ruleValue instanceof Enum<?> ruleEnum && actualValue instanceof Enum<?> actualEnum)
            return ruleEnum.name().equalsIgnoreCase(actualEnum.name());

        // ---- Numbers ----
        if (ruleValue instanceof Number ruleNum && actualValue instanceof Number actualNum)
            return ruleNum.doubleValue() == actualNum.doubleValue();

        // ---- Default ----
        return ruleValue.toString().trim().equalsIgnoreCase(actualValue.toString().trim());
    }

    // ---------- Extended algorithm + material matchers ----------

    private boolean matchAlgorithm(
            AlgorithmProperties actual, AlgorithmProperties rule, RuleDefinition r) {
        if (rule == null || actual == null) return false;
        boolean ok = true;
        ok &= fieldMatch("primitive", rule.getPrimitive(), actual.getPrimitive());
        ok &= fieldMatch("mode", rule.getMode(), actual.getMode());
        ok &= fieldMatch("padding", rule.getPadding(), actual.getPadding());

        // Range-aware parameter set
        if (r.getExpressionMap().containsKey("parameterSetIdentifier")) {
            ok &=
                    matches(
                            r.getExpressionMap().get("parameterSetIdentifier"),
                            actual.getParameterSetIdentifier());
        } else {
            ok &=
                    fieldMatch(
                            "parameterSetIdentifier",
                            rule.getParameterSetIdentifier(),
                            actual.getParameterSetIdentifier());
        }

        ok &= fieldMatch("curve", rule.getCurve(), actual.getCurve());
        ok &=
                fieldMatch(
                        "executionEnvironment",
                        rule.getExecutionEnvironment(),
                        actual.getExecutionEnvironment());
        ok &=
                fieldMatch(
                        "implementationPlatform",
                        rule.getImplementationPlatform(),
                        actual.getImplementationPlatform());
        ok &= fieldMatch("cryptoFunctions", rule.getCryptoFunctions(), actual.getCryptoFunctions());
        ok &=
                fieldMatch(
                        "classicalSecurityLevel",
                        rule.getClassicalSecurityLevel(),
                        actual.getClassicalSecurityLevel());
        ok &=
                fieldMatch(
                        "nistQuantumSecurityLevel",
                        rule.getNistQuantumSecurityLevel(),
                        actual.getNistQuantumSecurityLevel());
        return ok;
    }

    private boolean matchRelatedMaterial(
            RelatedCryptoMaterialProperties actual,
            RelatedCryptoMaterialProperties rule,
            RuleDefinition r) {
        if (rule == null || actual == null) return false;
        boolean ok = true;
        ok &= fieldMatch("type", rule.getType(), actual.getType());

        // Range-aware check for size
        if (r.getExpressionMap().containsKey("size")) {
            ok &= matches(r.getExpressionMap().get("size"), actual.getSize());
        } else {
            ok &= fieldMatch("size", rule.getSize(), actual.getSize());
        }

        ok &= fieldMatch("format", rule.getFormat(), actual.getFormat());
        return ok;
    }

    // ---------- Other matchers remain unchanged ----------

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
            result &= suiteMatch;
        }
        return result;
    }

    // ---------- Specificity remains unchanged ----------

    private int computeSpecificity(@Nonnull RuleDefinition rule) {
        int specificity = 0;
        if (rule.getName() != null && !rule.getName().isEmpty()) specificity++;

        CryptoProperties props = rule.getCryptoProperties();
        if (props != null) {
            if (props.getAssetType() != null) specificity++;

            AlgorithmProperties algo = props.getAlgorithmProperties();
            if (algo != null) {
                if (algo.getPrimitive() != null) specificity++;
                if (algo.getCryptoFunctions() != null && !algo.getCryptoFunctions().isEmpty())
                    specificity++;
                if (algo.getCurve() != null) specificity++;
                if (algo.getMode() != null) specificity++;
                if (algo.getPadding() != null) specificity++;
                if (algo.getNistQuantumSecurityLevel() != null) specificity++;
                if (algo.getParameterSetIdentifier() != null) specificity++;
                if (algo.getExecutionEnvironment() != null) specificity++;
                if (algo.getImplementationPlatform() != null) specificity++;
                if (algo.getCertificationLevel() != null) specificity++;
                if (algo.getClassicalSecurityLevel() != null) specificity++;
            }

            CertificateProperties cert = props.getCertificateProperties();
            if (cert != null) {
                if (cert.getSubjectName() != null) specificity++;
                if (cert.getIssuerName() != null) specificity++;
                if (cert.getNotValidBefore() != null) specificity++;
                if (cert.getNotValidAfter() != null) specificity++;
                if (cert.getSignatureAlgorithmRef() != null) specificity++;
                if (cert.getSubjectPublicKeyRef() != null) specificity++;
                if (cert.getCertificateFormat() != null) specificity++;
                if (cert.getCertificateExtension() != null) specificity++;
            }

            ProtocolProperties proto = props.getProtocolProperties();
            if (proto != null) {
                if (proto.getType() != null) specificity++;
                if (proto.getVersion() != null) specificity++;
                if (proto.getCipherSuites() != null && !proto.getCipherSuites().isEmpty())
                    specificity++;
            }

            RelatedCryptoMaterialProperties mat = props.getRelatedCryptoMaterialProperties();
            if (mat != null) {
                if (mat.getType() != null) specificity++;
                if (mat.getId() != null) specificity++;
                if (mat.getState() != null) specificity++;
                if (mat.getAlgorithmRef() != null) specificity++;
                if (mat.getCreationDate() != null) specificity++;
                if (mat.getActivationDate() != null) specificity++;
                if (mat.getUpdateDate() != null) specificity++;
                if (mat.getExpirationDate() != null) specificity++;
                if (mat.getValue() != null) specificity++;
                if (mat.getSize() != null) specificity++;
                if (mat.getFormat() != null) specificity++;
            }
        }
        return specificity;
    }
}
