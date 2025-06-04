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
        logger.debug("Parsing TOML policy...");
        TomlParseResult toml = Toml.parse(tomlString);

        // Fail fast if "levels" is missing
        if (!toml.contains("levels")) {
            throw new IllegalArgumentException("Missing required top-level array: levels");
        }

        CustomCompliancePolicy policy = new CustomCompliancePolicy();
        policy.setId(requireString(toml, "id"));
        policy.setName(requireString(toml, "name"));
        policy.setDefaultLevel(Math.toIntExact(requireLong(toml, "default_level")));

        logger.debug(
                "Policy ID: {}, Name: {}, Default Level: {}",
                policy.getId(),
                policy.getName(),
                policy.getDefaultLevel());

        // Parse compliance levels
        List<ComplianceLevel> levels = new ArrayList<>();
        TomlArray levelsArray = requireArray(toml, "levels");
        logger.debug("Parsing {} levels...", levelsArray.size());

        for (int i = 0; i < levelsArray.size(); i++) {
            TomlTable level = levelsArray.getTable(i);
            ComplianceLevel complianceLevel =
                    new ComplianceLevel(
                            requireInt(level, "id"),
                            requireString(level, "label"),
                            requireString(level, "description"),
                            requireString(level, "color"),
                            parseEnum(level, "icon", ComplianceIcon.class),
                            requireBoolean(level, "is_uncompliant"));
            levels.add(complianceLevel);
            logger.debug("Parsed level: {} (ID {})", complianceLevel.label(), complianceLevel.id());
        }
        policy.setLevels(levels);

        // Parse rules
        List<RuleDefinition> rules = new ArrayList<>();
        TomlArray rulesArray = requireArray(toml, "rule");
        logger.debug("Parsing {} rules...", rulesArray.size());

        for (int i = 0; i < rulesArray.size(); i++) {
            TomlTable table = rulesArray.getTable(i);
            RuleDefinition rule = new RuleDefinition();
            rule.setName(table.getString("name"));
            rule.setDescription(requireString(table, "description"));
            rule.setLevelId(requireInt(table, "level"));
            logger.debug(
                    "Rule {}: Level {}, Desc: {}", i + 1, rule.getLevelId(), rule.getDescription());

            CryptoProperties props = new CryptoProperties();
            props.setOid(table.getString("oid"));
            props.setAssetType(parseEnum(table, "asset_type", AssetType.class));
            logger.debug("  Asset type: {}", props.getAssetType());

            switch (props.getAssetType()) {
                case ALGORITHM -> {
                    AlgorithmProperties alg = new AlgorithmProperties();
                    if (table.contains("primitive")) {
                        alg.setPrimitive(parseEnum(table, "primitive", Primitive.class));
                        logger.debug("    Primitive: {}", alg.getPrimitive());
                    }
                    if (table.contains("mode")) {
                        alg.setMode(parseEnum(table, "mode", Mode.class));
                        logger.debug("    Mode: {}", alg.getMode());
                    }
                    if (table.contains("padding")) {
                        alg.setPadding(parseEnum(table, "padding", Padding.class));
                        logger.debug("    Padding: {}", alg.getPadding());
                    }
                    alg.setParameterSetIdentifier(table.getString("parameter_set_identifier"));
                    alg.setCurve(table.getString("curve"));
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
                                        table.getArray("crypto_functions"), CryptoFunction.class));
                    if (table.contains("certification_level"))
                        alg.setCertificationLevel(
                                toEnumList(
                                        table.getArray("certification_level"),
                                        CertificationLevel.class));
                    if (table.contains("classical_security_level"))
                        alg.setClassicalSecurityLevel(
                                Math.toIntExact(table.getLong("classical_security_level")));
                    if (table.contains("nist_quantum_security_level"))
                        alg.setNistQuantumSecurityLevel(
                                Math.toIntExact(table.getLong("nist_quantum_security_level")));
                    props.setAlgorithmProperties(alg);
                }
                case CERTIFICATE -> {
                    CertificateProperties cert = new CertificateProperties();
                    cert.setSubjectName(table.getString("subject_name"));
                    cert.setIssuerName(table.getString("issuer_name"));
                    cert.setNotValidBefore(table.getString("not_valid_before"));
                    cert.setNotValidAfter(table.getString("not_valid_after"));
                    cert.setSignatureAlgorithmRef(table.getString("signature_algorithm_ref"));
                    cert.setSubjectPublicKeyRef(table.getString("subject_public_key_ref"));
                    cert.setCertificateFormat(table.getString("certificate_format"));
                    cert.setCertificateExtension(table.getString("certificate_extension"));
                    props.setCertificateProperties(cert);
                }
                case PROTOCOL -> {
                    ProtocolProperties proto = new ProtocolProperties();
                    if (table.contains("type"))
                        proto.setType(parseEnum(table, "type", ProtocolType.class));
                    proto.setVersion(table.getString("version"));
                    if (table.contains("cipher_suites"))
                        proto.setCipherSuites(parseCipherSuites(table.getArray("cipher_suites")));
                    props.setProtocolProperties(proto);
                }
                case RELATED_CRYPTO_MATERIAL -> {
                    RelatedCryptoMaterialProperties mat = new RelatedCryptoMaterialProperties();
                    mat.setId(table.getString("id"));
                    if (table.contains("state"))
                        mat.setState(parseEnum(table, "state", State.class));
                    mat.setAlgorithmRef(table.getString("algorithm_ref"));
                    mat.setCreationDate(table.getString("creation_date"));
                    mat.setActivationDate(table.getString("activation_date"));
                    mat.setUpdateDate(table.getString("update_date"));
                    mat.setExpirationDate(table.getString("expiration_date"));
                    mat.setValue(table.getString("value"));
                    if (table.contains("size")) mat.setSize(Math.toIntExact(table.getLong("size")));
                    mat.setFormat(table.getString("format"));
                    props.setRelatedCryptoMaterialProperties(mat);
                }
            }

            rule.setCryptoProperties(props);
            rules.add(rule);
        }

        policy.setRules(rules);
        logger.debug("Parsing complete.");
        return policy;
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

    private static boolean requireBoolean(TomlTable table, String key) {
        Boolean value = table.getBoolean(key);
        if (value == null)
            throw new IllegalArgumentException("Missing required boolean field: " + key);
        return value;
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
