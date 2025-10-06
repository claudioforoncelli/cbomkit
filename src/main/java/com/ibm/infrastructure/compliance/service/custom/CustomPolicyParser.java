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

import com.ibm.infrastructure.compliance.AssessmentLevel;
import com.ibm.infrastructure.compliance.ComplianceLevel;
import com.ibm.infrastructure.compliance.ComplianceLevel.ComplianceIcon;
import java.util.*;
import java.util.stream.Collectors;
import org.cyclonedx.model.component.crypto.*;
import org.cyclonedx.model.component.crypto.enums.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tomlj.*;

public class CustomPolicyParser {

    private static final Logger logger = LoggerFactory.getLogger(CustomPolicyParser.class);

    public static CustomCompliancePolicy parse(String tomlString) {
        logger.info("Parsing TOML policy...");
        TomlParseResult toml = Toml.parse(tomlString);

        CustomCompliancePolicy policy = new CustomCompliancePolicy();
        policy.setId(requireString(toml, "id"));
        policy.setName(requireString(toml, "name"));
        policy.setDefaultLevel(Math.toIntExact(requireLong(toml, "default_assessment_level")));

        // ---- Assessment levels ----
        List<AssessmentLevel> assessmentLevels = new ArrayList<>();
        TomlArray assessmentLevelsArray = requireArray(toml, "assessment_levels");
        for (int i = 0; i < assessmentLevelsArray.size(); i++) {
            TomlTable level = assessmentLevelsArray.getTable(i);
            assessmentLevels.add(
                    new AssessmentLevel(requireInt(level, "id"), requireString(level, "label")));
        }
        policy.setAssessmentLevels(assessmentLevels);

        // ---- Compliance levels ----
        List<ComplianceLevel> levels = new ArrayList<>();
        TomlArray levelsArray = requireArray(toml, "compliance_levels");
        for (int i = 0; i < levelsArray.size(); i++) {
            TomlTable level = levelsArray.getTable(i);
            levels.add(
                    new ComplianceLevel(
                            requireInt(level, "id"),
                            requireString(level, "label"),
                            requireString(level, "description"),
                            requireString(level, "color"),
                            parseEnum(level, "icon", ComplianceIcon.class),
                            requireInt(level, "assessment_level")));
        }
        policy.setLevels(levels);

        // ---- Rules ----
        List<RuleDefinition> rules = new ArrayList<>();
        TomlArray rulesArray = requireArray(toml, "rule");

        for (int i = 0; i < rulesArray.size(); i++) {
            TomlTable table = rulesArray.getTable(i);
            RuleDefinition rule = new RuleDefinition();
            rule.setName(table.getString("name"));
            rule.setDescription(requireString(table, "description"));
            rule.setLevelId(requireInt(table, "compliance_level"));

            Map<String, String> expressions = new HashMap<>();

            CryptoProperties props = new CryptoProperties();
            props.setOid(table.getString("oid"));
            props.setAssetType(parseEnum(table, "asset_type", AssetType.class));

            switch (props.getAssetType()) {
                case ALGORITHM -> {
                    AlgorithmProperties alg = new AlgorithmProperties();

                    if (table.contains("primitive"))
                        alg.setPrimitive(parseEnum(table, "primitive", Primitive.class));
                    if (table.contains("mode")) alg.setMode(parseEnum(table, "mode", Mode.class));
                    if (table.contains("padding"))
                        alg.setPadding(parseEnum(table, "padding", Padding.class));

                    if (table.contains("parameter_set_identifier")) {
                        String val = table.getString("parameter_set_identifier");
                        alg.setParameterSetIdentifier(val);
                        if (containsRangeSymbols(val)) {
                            expressions.put("parameter_set_identifier", val);
                        }
                    }

                    if (table.contains("curve")) alg.setCurve(table.getString("curve"));

                    if (table.contains("execution_environment"))
                        alg.setExecutionEnvironment(
                                parseEnum(
                                        table,
                                        "execution_environment",
                                        ExecutionEnvironment.class));

                    if (table.contains("implementation_platform"))
                        alg.setImplementationPlatform(
                                parseEnum(
                                        table,
                                        "implementation_platform",
                                        ImplementationPlatform.class));

                    if (table.contains("crypto_functions"))
                        alg.setCryptoFunctions(
                                toEnumList(
                                        Objects.requireNonNull(table.getArray("crypto_functions")),
                                        CryptoFunction.class));

                    if (table.contains("certification_level"))
                        alg.setCertificationLevel(
                                toEnumList(
                                        Objects.requireNonNull(
                                                table.getArray("certification_level")),
                                        CertificationLevel.class));

                    if (table.contains("classical_security_level")) {
                        Object val = table.get("classical_security_level");
                        if (val instanceof Long l) alg.setClassicalSecurityLevel(l.intValue());
                        else if (val instanceof String s && containsRangeSymbols(s))
                            expressions.put("classical_security_level", s.trim());
                    }

                    if (table.contains("nist_quantum_security_level")) {
                        Object val = table.get("nist_quantum_security_level");
                        if (val instanceof Long l) alg.setNistQuantumSecurityLevel(l.intValue());
                        else if (val instanceof String s && containsRangeSymbols(s))
                            expressions.put("nist_quantum_security_level", s.trim());
                    }

                    props.setAlgorithmProperties(alg);
                }

                case RELATED_CRYPTO_MATERIAL -> {
                    RelatedCryptoMaterialProperties mat = new RelatedCryptoMaterialProperties();
                    if (table.contains("size")) {
                        Object val = table.get("size");
                        if (val instanceof Long l) mat.setSize(l.intValue());
                        else if (val instanceof String s && containsRangeSymbols(s))
                            expressions.put("size", s.trim());
                    }
                    props.setRelatedCryptoMaterialProperties(mat);
                }

                case CERTIFICATE -> {
                    CertificateProperties cert = new CertificateProperties();
                    cert.setSubjectName(table.getString("subject_name"));
                    cert.setIssuerName(table.getString("issuer_name"));
                    props.setCertificateProperties(cert);
                }

                case PROTOCOL -> {
                    ProtocolProperties proto = new ProtocolProperties();
                    proto.setVersion(table.getString("version"));
                    props.setProtocolProperties(proto);
                }
            }

            rule.setCryptoProperties(props);
            rule.setExpressionMap(expressions);
            rules.add(rule);
        }

        policy.setRules(rules);
        logger.info("Policy parsed successfully with {} rules.", rules.size());
        return policy;
    }

    // ---------- Utility Methods ----------

    private static boolean containsRangeSymbols(String s) {
        return s != null && (s.contains(">") || s.contains("<") || s.contains("="));
    }

    private static String requireString(TomlTable table, String key) {
        String value = table.getString(key);
        if (value == null)
            throw new IllegalArgumentException("Missing required string field: " + key);
        return value;
    }

    private static Long requireLong(TomlTable table, String key) {
        Long value = table.getLong(key);
        if (value == null)
            throw new IllegalArgumentException("Missing required long field: " + key);
        return value;
    }

    private static int requireInt(TomlTable table, String key) {
        return Math.toIntExact(requireLong(table, key));
    }

    private static TomlArray requireArray(TomlParseResult table, String key) {
        TomlArray array = table.getArray(key);
        if (array == null)
            throw new IllegalArgumentException("Missing required array field: " + key);
        return array;
    }

    private static <T extends Enum<T>> T parseEnum(TomlTable table, String key, Class<T> enumType) {
        String value = table.getString(key);
        if (value == null) throw new IllegalArgumentException("Missing enum field: " + key);
        try {
            return Enum.valueOf(enumType, value.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid value for enum " + key + ": " + value);
        }
    }

    private static <T extends Enum<T>> List<T> toEnumList(TomlArray array, Class<T> enumType) {
        return array.toList().stream()
                .map(v -> Enum.valueOf(enumType, v.toString().toUpperCase()))
                .collect(Collectors.toList());
    }

    private static List<CipherSuite> parseCipherSuites(TomlArray array) {
        return array.toList().stream()
                .map(
                        s -> {
                            CipherSuite cs = new CipherSuite();
                            cs.setName(s.toString());
                            return cs;
                        })
                .collect(Collectors.toList());
    }
}
