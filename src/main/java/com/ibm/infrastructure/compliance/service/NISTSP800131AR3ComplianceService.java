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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class NISTSP800131AR3ComplianceService implements IComplianceService {

    private static final Logger logger =
            LoggerFactory.getLogger(NISTSP800131AR3ComplianceService.class);

    @Nonnull private final Map<Integer, ComplianceLevel> complianceLevels;

    private final ComplianceLevel DISALLOWED;
    private final ComplianceLevel DEPRECATED;
    private final ComplianceLevel ACCEPTABLE;
    private final ComplianceLevel LEGACY_USE;
    private final ComplianceLevel UNKNOWN;

    public NISTSP800131AR3ComplianceService() {
        Map<Integer, ComplianceLevel> levels = new HashMap<>();
        levels.put(
                1,
                new ComplianceLevel(
                        1,
                        "Disallowed",
                        "Use is disallowed",
                        "#dc3545",
                        ComplianceLevel.ComplianceIcon.ERROR,
                        true));
        levels.put(
                2,
                new ComplianceLevel(
                        2,
                        "Deprecated",
                        "Use is discouraged and may be disallowed soon",
                        "#ffc107",
                        ComplianceLevel.ComplianceIcon.WARNING,
                        true));
        levels.put(
                3,
                new ComplianceLevel(
                        3,
                        "Acceptable",
                        null,
                        "green",
                        ComplianceLevel.ComplianceIcon.CHECKMARK_SECURE,
                        false));
        levels.put(
                4,
                new ComplianceLevel(
                        4,
                        "Legacy Use",
                        "Only allowed to decrypt/verify previously protected data",
                        "gray",
                        ComplianceLevel.ComplianceIcon.NOT_APPLICABLE,
                        false));
        levels.put(
                5,
                new ComplianceLevel(
                        5,
                        "Unknown",
                        "Could not determine compliance status",
                        "#17a9d1",
                        ComplianceLevel.ComplianceIcon.UNKNOWN,
                        true));

        this.complianceLevels = Collections.unmodifiableMap(levels);
        this.DISALLOWED = complianceLevels.get(1);
        this.DEPRECATED = complianceLevels.get(2);
        this.ACCEPTABLE = complianceLevels.get(3);
        this.LEGACY_USE = complianceLevels.get(4);
        this.UNKNOWN = complianceLevels.get(5);
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
        return UNKNOWN;
    }

    @Override
    public @Nonnull ComplianceCheckResultDTO evaluate(
            @Nonnull PolicyIdentifier policyIdentifier,
            @Nonnull Collection<CryptographicAsset> cryptographicAssets) {

        if (!"nist_sp_800_131_ar3".equals(policyIdentifier.id())) {
            return new ComplianceCheckResultDTO(List.of(), true);
        }

        List<ICryptographicAssetPolicyResult> results =
                cryptographicAssets.stream().map(this::evaluate).toList();

        logger.debug("==== NIST SP800-131A Rev. 3 Compliance Evaluation ====");
        for (ICryptographicAssetPolicyResult result : results) {
            logger.debug(
                    "Asset ID: {}\n  Compliance Level: {}\n  Description: {}",
                    result.identifier(),
                    result.complianceLevel().label(),
                    result.message());
        }
        logger.debug("======================================================");

        return new ComplianceCheckResultDTO(results, false);
    }

    @Nonnull
    private ICryptographicAssetPolicyResult evaluate(@Nonnull CryptographicAsset asset) {
        final String assetId = asset.identifier();
        final CryptoProperties props = asset.component().getCryptoProperties();
        final AlgorithmProperties alg = props.getAlgorithmProperties();

        final String name =
                Optional.ofNullable(asset.component().getName()).orElse("").toLowerCase();
        final String mode =
                alg != null && alg.getMode() != null ? alg.getMode().toString().toLowerCase() : "";

        logger.debug("Evaluating asset: {}\n  Name: {}\n  Mode: {}", assetId, name, mode);

        if (name.contains("sha1")) {
            logger.debug("  Matched rule: SHA-1 is deprecated");
            return new BasicCryptographicAssetPolicyResult(
                    assetId,
                    DEPRECATED,
                    "SHA-1 is deprecated and disallowed after 2030, as specified in section 1.2 of the guideline.");
        }

        if (name.contains("sha224")) {
            logger.debug("  Matched rule: SHA-224 is deprecated");
            return new BasicCryptographicAssetPolicyResult(
                    assetId,
                    DEPRECATED,
                    "SHA-224 is deprecated and disallowed after 2030, as specified in section 1.2 of the guideline.");
        }

        if (name.contains("aes")) {
            logger.debug("  Matched rule: AES is acceptable");
            return new BasicCryptographicAssetPolicyResult(
                    assetId,
                    ACCEPTABLE,
                    "AES is acceptable at all key sizes (128+), as specified in section 2.1 of the guideline.");
        }

        if (name.contains("tdea") || name.contains("3des") || name.contains("triple des")) {
            logger.debug("  Matched rule: TDEA is disallowed");
            return new BasicCryptographicAssetPolicyResult(
                    assetId,
                    DISALLOWED,
                    "TDEA is disallowed, as specified in section 2.1 of the guideline.");
        }

        if (mode.contains("ecb")) {
            logger.debug("  Matched rule: ECB mode (legacy use)");
            return new BasicCryptographicAssetPolicyResult(
                    assetId,
                    LEGACY_USE,
                    "ECB mode is disallowed for encryption but allowed as legacy use for decryption, as specified in section 2.2 of the guideline.");
        } else if (mode.contains("cbc")) {
            logger.debug("  Matched rule: CBC mode is acceptable");
            return new BasicCryptographicAssetPolicyResult(
                    assetId,
                    ACCEPTABLE,
                    "CBC mode is acceptable, as specified in section 2.2 of the guideline.");
        } else if (mode.contains("cfb")) {
            logger.debug("  Matched rule: CFB mode is acceptable");
            return new BasicCryptographicAssetPolicyResult(
                    assetId,
                    ACCEPTABLE,
                    "CFB mode is acceptable, as specified in section 2.2 of the guideline.");
        } else if (mode.contains("ctr")) {
            logger.debug("  Matched rule: CTR mode is acceptable");
            return new BasicCryptographicAssetPolicyResult(
                    assetId,
                    ACCEPTABLE,
                    "CTR mode is acceptable, as specified in section 2.2 of the guideline.");
        } else if (mode.contains("ofb")) {
            logger.debug("  Matched rule: OFB mode is acceptable");
            return new BasicCryptographicAssetPolicyResult(
                    assetId,
                    ACCEPTABLE,
                    "OFB mode is acceptable, as specified in section 2.2 of the guideline.");
        } else if (mode.contains("ccm")) {
            logger.debug("  Matched rule: CCM mode is acceptable");
            return new BasicCryptographicAssetPolicyResult(
                    assetId,
                    ACCEPTABLE,
                    "CCM mode is acceptable, as specified in section 2.2 of the guideline.");
        } else if (mode.contains("gcm")) {
            logger.debug("  Matched rule: GCM mode is acceptable");
            return new BasicCryptographicAssetPolicyResult(
                    assetId,
                    ACCEPTABLE,
                    "GCM mode is acceptable, as specified in section 2.2 of the guideline.");
        } else if (mode.contains("xts")) {
            logger.debug("  Matched rule: XTS mode is acceptable");
            return new BasicCryptographicAssetPolicyResult(
                    assetId,
                    ACCEPTABLE,
                    "XTS-AES mode is acceptable, as specified in section 2.2 of the guideline.");
        } else if (mode.contains("ff3")) {
            logger.debug("  Matched rule: FF3 mode is disallowed");
            return new BasicCryptographicAssetPolicyResult(
                    assetId,
                    DISALLOWED,
                    "FF3 mode is disallowed, as specified in section 2.2 of the guideline.");
        }

        logger.debug("  No rule matched. Returning 'Unknown'");
        return new BasicCryptographicAssetPolicyResult(
                assetId, UNKNOWN, "Could not categorize this asset");
    }
}
