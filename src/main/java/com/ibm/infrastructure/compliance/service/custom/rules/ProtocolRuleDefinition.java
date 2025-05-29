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
import java.util.Map;
import org.cyclonedx.model.component.crypto.CipherSuite;
import org.cyclonedx.model.component.crypto.CryptoRef;
import org.cyclonedx.model.component.crypto.enums.ProtocolType;

public class ProtocolRuleDefinition {
    private ProtocolType type;
    private String version;
    private List<CipherSuite> cipherSuites;
    private Map<String, CryptoRef> ikev2TransformTypes;
    private CryptoRef cryptoRefArray;
    private int levelId;
    private String description;

    public ProtocolType getType() {
        return type;
    }

    public void setType(ProtocolType type) {
        this.type = type;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public List<CipherSuite> getCipherSuites() {
        return cipherSuites;
    }

    public void setCipherSuites(List<CipherSuite> cipherSuites) {
        this.cipherSuites = cipherSuites;
    }

    public Map<String, CryptoRef> getIkev2TransformTypes() {
        return ikev2TransformTypes;
    }

    public void setIkev2TransformTypes(Map<String, CryptoRef> ikev2TransformTypes) {
        this.ikev2TransformTypes = ikev2TransformTypes;
    }

    public CryptoRef getCryptoRefArray() {
        return cryptoRefArray;
    }

    public void setCryptoRefArray(CryptoRef cryptoRefArray) {
        this.cryptoRefArray = cryptoRefArray;
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
