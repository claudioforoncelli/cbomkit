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
package com.ibm.infrastructure.compliance.service.custom.rules;

import java.util.List;

public class AlgorithmRuleDefinition {
    private String primitive;
    private String parameterSetIdentifier;
    private String curve;
    private String executionEnvironment;
    private String implementationPlatform;
    private List<String> certificationLevel;
    private String mode;
    private String padding;
    private List<String> cryptoFunctions;
    private Integer classicalSecurityLevel;
    private Integer nistQuantumSecurityLevel;
    private int levelId;
    private String description;

    public String getPrimitive() {
        return primitive;
    }

    public void setPrimitive(String primitive) {
        this.primitive = primitive;
    }

    public String getParameterSetIdentifier() {
        return parameterSetIdentifier;
    }

    public void setParameterSetIdentifier(String parameterSetIdentifier) {
        this.parameterSetIdentifier = parameterSetIdentifier;
    }

    public String getCurve() {
        return curve;
    }

    public void setCurve(String curve) {
        this.curve = curve;
    }

    public String getExecutionEnvironment() {
        return executionEnvironment;
    }

    public void setExecutionEnvironment(String executionEnvironment) {
        this.executionEnvironment = executionEnvironment;
    }

    public String getImplementationPlatform() {
        return implementationPlatform;
    }

    public void setImplementationPlatform(String implementationPlatform) {
        this.implementationPlatform = implementationPlatform;
    }

    public List<String> getCertificationLevel() {
        return certificationLevel;
    }

    public void setCertificationLevel(List<String> certificationLevel) {
        this.certificationLevel = certificationLevel;
    }

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    public String getPadding() {
        return padding;
    }

    public void setPadding(String padding) {
        this.padding = padding;
    }

    public List<String> getCryptoFunctions() {
        return cryptoFunctions;
    }

    public void setCryptoFunctions(List<String> cryptoFunctions) {
        this.cryptoFunctions = cryptoFunctions;
    }

    public Integer getClassicalSecurityLevel() {
        return classicalSecurityLevel;
    }

    public void setClassicalSecurityLevel(Integer classicalSecurityLevel) {
        this.classicalSecurityLevel = classicalSecurityLevel;
    }

    public Integer getNistQuantumSecurityLevel() {
        return nistQuantumSecurityLevel;
    }

    public void setNistQuantumSecurityLevel(Integer nistQuantumSecurityLevel) {
        this.nistQuantumSecurityLevel = nistQuantumSecurityLevel;
    }

    public int getLevelId() {
        return levelId;
    }

    public void setLevelId(int levelId) {
        this.levelId = levelId;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}
