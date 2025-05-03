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

import com.ibm.domain.compliance.CryptographicAsset;
import com.ibm.domain.compliance.PolicyIdentifier;
import com.ibm.infrastructure.compliance.ComplianceLevel;
import jakarta.annotation.Nonnull;
import java.util.*;
import org.cyclonedx.model.component.crypto.AlgorithmProperties;
import org.cyclonedx.model.component.crypto.CryptoProperties;

public class NISTSP800131AR3ComplianceService implements IComplianceService {
    @Nonnull private final Map<Integer, ComplianceLevel> complianceLevels;

    public NISTSP800131AR3ComplianceService() {
        complianceLevels = new HashMap<>();
        complianceLevels.put(
                1,
                new ComplianceLevel(
                        1,
                        "Disallowed",
                        null,
                        "#dc3545",
                        ComplianceLevel.ComplianceIcon.ERROR,
                        true));
        complianceLevels.put(
                2,
                new ComplianceLevel(
                        2,
                        "Deprecated",
                        "Use is discouraged and may be disallowed soon",
                        "#ffc107",
                        ComplianceLevel.ComplianceIcon.WARNING,
                        true));
        complianceLevels.put(
                3,
                new ComplianceLevel(
                        3,
                        "Acceptable",
                        null,
                        "green",
                        ComplianceLevel.ComplianceIcon.CHECKMARK_SECURE,
                        false));
        complianceLevels.put(
                4,
                new ComplianceLevel(
                        4,
                        "Legacy Use",
                        "Only allowed to decrypt/verify previously protected data",
                        "gray",
                        ComplianceLevel.ComplianceIcon.NOT_APPLICABLE,
                        false));
        complianceLevels.put(
                5,
                new ComplianceLevel(
                        5,
                        "Unknown",
                        "Could not determine compliance status",
                        "#17a9d1",
                        ComplianceLevel.ComplianceIcon.UNKNOWN,
                        true));
    }

    @Nonnull
    @Override
    public String getName() {
        return "NIST SP 800-131A Rev. 3 Compliance";
    }

    @Nonnull
    @Override
    public List<ComplianceLevel> getComplianceLevels() {
        return new ArrayList<>(complianceLevels.values());
    }

    @Nonnull
    @Override
    public ComplianceLevel getDefaultComplianceLevel() {
        return this.complianceLevels.get(5);
    }

    @Override
    public @Nonnull ComplianceCheckResultDTO evaluate(
            @Nonnull PolicyIdentifier policyIdentifier,
            @Nonnull Collection<CryptographicAsset> cryptographicAssets) {
        if (!policyIdentifier.id().equals("nist_sp_800_131_ar3")) {
            return new ComplianceCheckResultDTO(List.of(), true);
        }
        return new ComplianceCheckResultDTO(
                cryptographicAssets.stream().map(this::evaluate).toList(), false);
    }

    @SuppressWarnings("java:S3776")
    @Nonnull
    private ICryptographicAssetPolicyResult evaluate(
            @Nonnull CryptographicAsset cryptographicAsset) {
        final CryptoProperties cryptoProperties =
                cryptographicAsset.component().getCryptoProperties();
        final AlgorithmProperties algorithmProperties = cryptoProperties.getAlgorithmProperties();
        final String name =
                cryptographicAsset.component().getName() != null
                        ? cryptographicAsset.component().getName().toLowerCase()
                        : "";
        final String mode =
                algorithmProperties != null && algorithmProperties.getMode() != null
                        ? algorithmProperties.getMode().toString().toLowerCase()
                        : "";

        // Rule: SHA-1 and SHA-224 are deprecated (disallowed after 2030)
        if (name.contains("sha1")) {
            return new BasicCryptographicAssetPolicyResult(
                    cryptographicAsset.identifier(),
                    complianceLevels.get(2),
                    "SHA-1 is deprecated and disallowed after 2030");
        } else if (name.contains("sha224")) {
            return new BasicCryptographicAssetPolicyResult(
                    cryptographicAsset.identifier(),
                    complianceLevels.get(2),
                    "SHA-224 is deprecated and disallowed after 2030");
        }

        // Rule: AES is always acceptable
        if (name.contains("aes")) {
            return new BasicCryptographicAssetPolicyResult(
                    cryptographicAsset.identifier(),
                    complianceLevels.get(3),
                    "AES is acceptable at all key sizes (128+)");
        }

        // Rule: TDEA is disallowed
        if (name.contains("tdea") || name.contains("3des") || name.contains("triple des")) {
            return new BasicCryptographicAssetPolicyResult(
                    cryptographicAsset.identifier(), complianceLevels.get(1), "TDEA is disallowed");
        }

        // Modes
        if (mode.contains("ecb")) {
            return new BasicCryptographicAssetPolicyResult(
                    cryptographicAsset.identifier(),
                    complianceLevels.get(4),
                    "ECB mode is disallowed for encryption but "
                            + "allowed as legacy use for decryption");
        } else if (mode.contains("cbc")) {
            return new BasicCryptographicAssetPolicyResult(
                    cryptographicAsset.identifier(),
                    complianceLevels.get(3),
                    "CBC mode is acceptable");
        } else if (mode.contains("cfb")) {
            return new BasicCryptographicAssetPolicyResult(
                    cryptographicAsset.identifier(),
                    complianceLevels.get(3),
                    "CFB mode is acceptable");
        } else if (mode.contains("ctr")) {
            return new BasicCryptographicAssetPolicyResult(
                    cryptographicAsset.identifier(),
                    complianceLevels.get(3),
                    "CTR mode is acceptable");
        } else if (mode.contains("ofb")) {
            return new BasicCryptographicAssetPolicyResult(
                    cryptographicAsset.identifier(),
                    complianceLevels.get(3),
                    "OFB mode is acceptable");
        } else if (mode.contains("ccm")) {
            return new BasicCryptographicAssetPolicyResult(
                    cryptographicAsset.identifier(),
                    complianceLevels.get(3),
                    "CCM mode is acceptable");
        } else if (mode.contains("gcm")) {
            return new BasicCryptographicAssetPolicyResult(
                    cryptographicAsset.identifier(),
                    complianceLevels.get(3),
                    "GCM mode is acceptable");
        } else if (mode.contains("xts")) {
            return new BasicCryptographicAssetPolicyResult(
                    cryptographicAsset.identifier(),
                    complianceLevels.get(3),
                    "XTS-AES mode is acceptable");
        } else if (mode.contains("ff3")) {
            return new BasicCryptographicAssetPolicyResult(
                    cryptographicAsset.identifier(),
                    complianceLevels.get(1),
                    "FF3 mode is disallowed");
        }

        // Default fallback
        return new BasicCryptographicAssetPolicyResult(
                cryptographicAsset.identifier(),
                complianceLevels.get(5),
                "Could not categorize this asset");
    }
}
