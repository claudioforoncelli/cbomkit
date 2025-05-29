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

public class CertificateRuleDefinition {
    private String subjectName;
    private String issuerName;
    private String notValidBefore;
    private String notValidAfter;
    private String signatureAlgorithmRef;
    private String subjectPublicKeyRef;
    private String certificateFormat;
    private String certificateExtension;
    private int levelId;
    private String description;

    public String getSubjectName() {
        return subjectName;
    }

    public void setSubjectName(String subjectName) {
        this.subjectName = subjectName;
    }

    public String getIssuerName() {
        return issuerName;
    }

    public void setIssuerName(String issuerName) {
        this.issuerName = issuerName;
    }

    public String getNotValidBefore() {
        return notValidBefore;
    }

    public void setNotValidBefore(String notValidBefore) {
        this.notValidBefore = notValidBefore;
    }

    public String getNotValidAfter() {
        return notValidAfter;
    }

    public void setNotValidAfter(String notValidAfter) {
        this.notValidAfter = notValidAfter;
    }

    public String getSignatureAlgorithmRef() {
        return signatureAlgorithmRef;
    }

    public void setSignatureAlgorithmRef(String signatureAlgorithmRef) {
        this.signatureAlgorithmRef = signatureAlgorithmRef;
    }

    public String getSubjectPublicKeyRef() {
        return subjectPublicKeyRef;
    }

    public void setSubjectPublicKeyRef(String subjectPublicKeyRef) {
        this.subjectPublicKeyRef = subjectPublicKeyRef;
    }

    public String getCertificateFormat() {
        return certificateFormat;
    }

    public void setCertificateFormat(String certificateFormat) {
        this.certificateFormat = certificateFormat;
    }

    public String getCertificateExtension() {
        return certificateExtension;
    }

    public void setCertificateExtension(String certificateExtension) {
        this.certificateExtension = certificateExtension;
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
