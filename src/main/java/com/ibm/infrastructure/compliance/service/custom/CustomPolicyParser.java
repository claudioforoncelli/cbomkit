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
import java.util.ArrayList;
import java.util.List;
import org.tomlj.Toml;
import org.tomlj.TomlArray;
import org.tomlj.TomlParseResult;

public class CustomPolicyParser {

    public static CustomCompliancePolicy parse(String tomlString) {
        TomlParseResult toml = Toml.parse(tomlString);
        CustomCompliancePolicy policy = new CustomCompliancePolicy();

        policy.id = toml.getString("id");
        policy.name = toml.getString("name");
        policy.defaultLevel = toml.getString("default_level");

        // Parse levels
        TomlArray levelsArray = toml.getArray("levels");
        List<ComplianceLevel> levels = new ArrayList<>();
        for (int i = 0; i < levelsArray.size(); i++) {
            var table = levelsArray.getTable(i);
            String label = table.getString("id"); // Use string ID as label
            levels.add(
                    new ComplianceLevel(
                            i + 1, // Auto-incremented numeric ID
                            label,
                            table.getString("description"),
                            table.getString("color"),
                            ComplianceIcon.UNKNOWN, // Default icon
                            table.getBoolean("is_uncompliant")));
        }
        policy.levels = levels;

        policy.primitives = parseRuleArray(toml.getArray("primitives"));
        policy.modes = parseRuleArray(toml.getArray("modes"));
        policy.signatures = parseRuleArray(toml.getArray("signatures"));
        policy.cipherSuites = parseRuleArray(toml.getArray("cipher_suites"));
        policy.contexts = parseRuleArray(toml.getArray("contexts"));

        return policy;
    }

    private static List<RuleDefinition> parseRuleArray(TomlArray array) {
        List<RuleDefinition> rules = new ArrayList<>();
        if (array == null) return rules;
        for (int i = 0; i < array.size(); i++) {
            var table = array.getTable(i);
            RuleDefinition rule = new RuleDefinition();
            rule.name = table.getString("name");
            rule.level = table.getString("level");
            rule.description = table.getString("description");
            rules.add(rule);
        }
        return rules;
    }
}
