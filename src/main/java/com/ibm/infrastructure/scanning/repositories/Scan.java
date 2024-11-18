/*
 * CBOMkit
 * Copyright (C) 2024 IBM
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
package com.ibm.infrastructure.scanning.repositories;

import com.ibm.domain.scanning.CBOM;
import com.ibm.domain.scanning.Commit;
import com.ibm.domain.scanning.GitUrl;
import com.ibm.domain.scanning.Language;
import com.ibm.domain.scanning.LanguageScan;
import com.ibm.domain.scanning.Revision;
import com.ibm.domain.scanning.ScanAggregate;
import com.ibm.domain.scanning.ScanId;
import com.ibm.domain.scanning.ScanMetadata;
import com.ibm.domain.scanning.ScanRequest;
import com.ibm.domain.scanning.errors.CBOMSerializationFailed;
import io.quarkus.hibernate.orm.panache.PanacheEntityBase;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.persistence.Cacheable;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Entity
@Cacheable
class Scan extends PanacheEntityBase {
    private static final Logger LOGGER = LoggerFactory.getLogger(Scan.class);

    @Id @Nonnull public UUID id;

    @Nonnull public String gitUrl;
    @Nonnull public String revision;
    @Nullable public String commitHash;
    @Nullable public String subFolder;

    @OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER)
    @Nonnull
    public Collection<ScanResult> scanResults;

    protected Scan() {}

    Scan(@Nonnull ScanAggregate aggregate) {
        this.id = aggregate.getId().getUuid();
        this.gitUrl = aggregate.getScanRequest().gitUrl().value();
        this.revision = aggregate.getScanRequest().revision().value();
        this.commitHash = aggregate.getCommit().map(Commit::hash).orElse(null);
        this.subFolder = aggregate.getScanRequest().subFolder();

        final Optional<List<LanguageScan>> languageScans = aggregate.getLanguageScans();
        if (languageScans.isEmpty()) {
            scanResults = new ArrayList<>();
            return;
        }

        final List<ScanResult> scanResultList = new ArrayList<>();
        for (LanguageScan languageScan : languageScans.get()) {
            try {
                final ScanResult scanResult =
                        new ScanResult(
                                languageScan.language(),
                                languageScan.scanMetadata().startTime(),
                                languageScan.scanMetadata().endTime(),
                                languageScan.scanMetadata().numberOfScannedLines(),
                                languageScan.scanMetadata().numberOfScannedFiles(),
                                languageScan.icbom().toJSON());
                scanResultList.add(scanResult);
            } catch (CBOMSerializationFailed e) {
                LOGGER.error(e.getMessage());
            }
        }
        this.scanResults = scanResultList;
    }

    @Nonnull
    protected ScanAggregate asAggregate() {
        final Map<Language, LanguageScan> languageScans = new EnumMap<>(Language.class);
        for (ScanResult scanResult : scanResults) {
            try {
                final LanguageScan languageScan =
                        new LanguageScan(
                                scanResult.language,
                                new ScanMetadata(
                                        scanResult.startTime.getTime(),
                                        scanResult.endTime.getTime(),
                                        scanResult.numberOfScannedLines,
                                        scanResult.numberOfScannedFiles),
                                CBOM.formJSON(scanResult.cbom));
                languageScans.put(languageScan.language(), languageScan);
            } catch (CBOMSerializationFailed e) {
                LOGGER.error(e.getMessage());
            }
        }
        return ScanAggregate.reconstruct(
                new ScanId(this.id),
                new ScanRequest(
                        new GitUrl(this.gitUrl), new Revision(this.revision), this.subFolder),
                Optional.ofNullable(this.commitHash).map(Commit::new).orElse(null),
                languageScans);
    }
}
