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

import java.util.HashMap;
import java.util.Map;
import org.cyclonedx.model.component.crypto.CryptoProperties;

public class RuleDefinition {
    private String name;
    private CryptoProperties cryptoProperties;
    private String description;
    private Integer levelId;

    // allows storing additional expressions like ">=128 <512"
    private Map<String, String> expressionMap = new HashMap<>();

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public CryptoProperties getCryptoProperties() {
        return cryptoProperties;
    }

    public void setCryptoProperties(CryptoProperties cryptoProperties) {
        this.cryptoProperties = cryptoProperties;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Integer getLevelId() {
        return levelId;
    }

    public void setLevelId(Integer levelId) {
        this.levelId = levelId;
    }

    public Map<String, String> getExpressionMap() {
        return expressionMap;
    }

    public void setExpressionMap(Map<String, String> expressionMap) {
        this.expressionMap = expressionMap;
    }
}
