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
import com.ibm.infrastructure.compliance.service.custom.rules.*;
import java.util.*;
import java.util.stream.Collectors;
import org.cyclonedx.model.component.crypto.CipherSuite;
import org.cyclonedx.model.component.crypto.CryptoRef;
import org.cyclonedx.model.component.crypto.enums.ProtocolType;
import org.cyclonedx.model.component.crypto.enums.RelatedCryptoMaterialType;
import org.cyclonedx.model.component.crypto.enums.State;
import org.tomlj.Toml;
import org.tomlj.TomlArray;
import org.tomlj.TomlParseResult;

public class CustomPolicyParser {

    public static CustomCompliancePolicy parse(String tomlString) {
        TomlParseResult toml = Toml.parse(tomlString);
        CustomCompliancePolicy policy = new CustomCompliancePolicy();

        policy.setId(toml.getString("id"));
        policy.setName(toml.getString("name"));
        policy.setDefaultLevel(
                toml.getLong("default_level") != null
                        ? toml.getLong("default_level").intValue()
                        : 0);

        TomlArray levelsArray = toml.getArray("levels");
        List<ComplianceLevel> levels = new ArrayList<>();
        for (int i = 0; i < levelsArray.size(); i++) {
            var table = levelsArray.getTable(i);
            int id = table.getLong("id") != null ? table.getLong("id").intValue() : 0;
            String label = table.getString("label");
            String description = table.getString("description");
            String color = table.getString("color");
            String iconString = table.getString("icon");
            boolean isUncompliant = Boolean.TRUE.equals(table.getBoolean("is_uncompliant"));

            ComplianceIcon icon;
            try {
                icon = ComplianceIcon.valueOf(iconString.toUpperCase());
            } catch (Exception e) {
                icon = ComplianceIcon.UNKNOWN;
            }

            levels.add(new ComplianceLevel(id, label, description, color, icon, isUncompliant));
        }
        policy.setLevels(levels);

        policy.setAlgorithmRules(parseAlgorithmRuleArray(toml.getArray("algorithm")));
        policy.setCertificateRules(parseCertificateRuleArray(toml.getArray("certificate")));
        policy.setProtocolRules(parseProtocolRuleArray(toml.getArray("protocol")));
        policy.setRelatedCryptoMaterialRules(
                parseRelatedCryptoMaterialRuleArray(toml.getArray("crypto_material")));

        System.out.println("Loaded " + policy.getAlgorithmRules().size() + " algorithm rules");

        policy.setHashAlgorithms(parseRuleArray(toml.getArray("hash_algorithms")));

        return policy;
    }

    private static List<AlgorithmRuleDefinition> parseAlgorithmRuleArray(TomlArray array) {
        List<AlgorithmRuleDefinition> rules = new ArrayList<>();
        if (array == null) return rules;
        for (int i = 0; i < array.size(); i++) {
            var table = array.getTable(i);
            AlgorithmRuleDefinition rule = new AlgorithmRuleDefinition();

            rule.setPrimitive(table.getString("primitive"));
            rule.setParameterSetIdentifier(table.getString("parameter_set_identifier"));
            rule.setCurve(table.getString("curve"));
            rule.setExecutionEnvironment(table.getString("execution_environment"));
            rule.setImplementationPlatform(table.getString("implementation_platform"));
            rule.setMode(table.getString("mode"));
            rule.setPadding(table.getString("padding"));
            rule.setDescription(table.getString("description"));
            Long levelLong = table.getLong("level");
            if (levelLong == null) {
                throw new IllegalArgumentException(
                        "Missing 'level' field in algorithm rule: " + table);
            }
            rule.setLevelId(levelLong.intValue());

            rule.setCertificationLevel(
                    table.getArray("certification_level") != null
                            ? table.getArray("certification_level").toList().stream()
                                    .map(Object::toString)
                                    .collect(Collectors.toList())
                            : null);

            rule.setCryptoFunctions(
                    table.getArray("crypto_functions") != null
                            ? table.getArray("crypto_functions").toList().stream()
                                    .map(Object::toString)
                                    .collect(Collectors.toList())
                            : null);

            rule.setClassicalSecurityLevel(
                    table.contains("classical_security_level")
                                    && table.getLong("classical_security_level") != null
                            ? table.getLong("classical_security_level").intValue()
                            : null);

            rule.setNistQuantumSecurityLevel(
                    table.contains("nist_quantum_security_level")
                                    && table.getLong("nist_quantum_security_level") != null
                            ? table.getLong("nist_quantum_security_level").intValue()
                            : null);

            System.out.println(
                    "Loaded algorithm rule: '"
                            + rule.getDescription()
                            + "' with level "
                            + rule.getLevelId());

            rules.add(rule);
        }
        return rules;
    }

    private static List<CertificateRuleDefinition> parseCertificateRuleArray(TomlArray array) {
        List<CertificateRuleDefinition> rules = new ArrayList<>();
        if (array == null) return rules;

        for (int i = 0; i < array.size(); i++) {
            var table = array.getTable(i);
            CertificateRuleDefinition rule = new CertificateRuleDefinition();

            rule.setSubjectName(table.getString("subject_name"));
            rule.setIssuerName(table.getString("issuer_name"));
            rule.setNotValidBefore(table.getString("not_valid_before"));
            rule.setNotValidAfter(table.getString("not_valid_after"));
            rule.setSignatureAlgorithmRef(table.getString("signature_algorithm_ref"));
            rule.setSubjectPublicKeyRef(table.getString("subject_public_key_ref"));
            rule.setCertificateFormat(table.getString("certificate_format"));
            rule.setCertificateExtension(table.getString("certificate_extension"));
            rule.setLevelId(table.getLong("level") != null ? table.getLong("level").intValue() : 0);
            rule.setDescription(table.getString("description"));

            rules.add(rule);
        }

        return rules;
    }

    private static List<ProtocolRuleDefinition> parseProtocolRuleArray(TomlArray array) {
        List<ProtocolRuleDefinition> rules = new ArrayList<>();
        if (array == null) return rules;

        for (int i = 0; i < array.size(); i++) {
            var table = array.getTable(i);
            ProtocolRuleDefinition rule = new ProtocolRuleDefinition();

            if (table.contains("type")) {
                rule.setType(ProtocolType.valueOf(table.getString("type").toUpperCase()));
            }

            rule.setVersion(table.getString("version"));

            if (table.contains("cipher_suites")) {
                List<CipherSuite> suites =
                        table.getArray("cipher_suites").toList().stream()
                                .map(
                                        cs -> {
                                            CipherSuite suite = new CipherSuite();
                                            suite.setName(cs.toString());
                                            return suite;
                                        })
                                .collect(Collectors.toList());
                rule.setCipherSuites(suites);
            }

            if (table.contains("ikev2_transform_types")) {
                Map<String, CryptoRef> transforms = new HashMap<>();
                var ikev2Table = table.getTable("ikev2_transform_types");
                for (String key : ikev2Table.keySet()) {
                    CryptoRef ref = new CryptoRef();
                    ref.setRef(Collections.singletonList(ikev2Table.getString(key)));
                    transforms.put(key, ref);
                }
                rule.setIkev2TransformTypes(transforms);
            }

            rule.setLevelId(table.getLong("level") != null ? table.getLong("level").intValue() : 0);
            rule.setDescription(table.getString("description"));

            rules.add(rule);
        }

        return rules;
    }

    private static List<RelatedCryptoMaterialRules> parseRelatedCryptoMaterialRuleArray(
            TomlArray array) {
        List<RelatedCryptoMaterialRules> rules = new ArrayList<>();
        if (array == null) return rules;

        for (int i = 0; i < array.size(); i++) {
            var table = array.getTable(i);
            RelatedCryptoMaterialRules rule = new RelatedCryptoMaterialRules();

            if (table.contains("type")) {
                rule.setType(
                        RelatedCryptoMaterialType.valueOf(table.getString("type").toUpperCase()));
            }

            rule.setId(table.getString("id"));

            if (table.contains("state")) {
                rule.setState(State.valueOf(table.getString("state").toUpperCase()));
            }

            rule.setAlgorithmRef(table.getString("algorithm_ref"));
            rule.setCreationDate(table.getString("creation_date"));
            rule.setActivationDate(table.getString("activation_date"));
            rule.setUpdateDate(table.getString("update_date"));
            rule.setExpirationDate(table.getString("expiration_date"));
            rule.setValue(table.getString("value"));
            rule.setSize(
                    table.contains("size") && table.getLong("size") != null
                            ? table.getLong("size").intValue()
                            : null);
            rule.setFormat(table.getString("format"));

            rule.setLevelId(table.getLong("level") != null ? table.getLong("level").intValue() : 0);
            rule.setDescription(table.getString("description"));

            rules.add(rule);
        }

        return rules;
    }

    private static List<RuleDefinition> parseRuleArray(TomlArray array) {
        List<RuleDefinition> rules = new ArrayList<>();
        if (array == null) return rules;
        for (int i = 0; i < array.size(); i++) {
            var table = array.getTable(i);
            RuleDefinition rule = new RuleDefinition();
            rule.name = table.getString("name");
            rule.levelId = table.getLong("level") != null ? table.getLong("level").intValue() : 0;
            rule.description = table.getString("description");
            rules.add(rule);
        }
        return rules;
    }
}
