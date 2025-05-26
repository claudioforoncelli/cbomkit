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
package com.ibm.infrastructure.compliance;

import com.ibm.infrastructure.compliance.service.BasicQuantumSafeComplianceService;
import com.ibm.infrastructure.compliance.service.IComplianceService;
import com.ibm.infrastructure.compliance.service.NISTSP800131AR3ComplianceService;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@ApplicationScoped
public class ComplianceServiceSelector {

    private final Map<String, IComplianceService> services = new HashMap<>();
    private IComplianceService defaultService;

    @PostConstruct
    public void init() {
        // Instantiate available compliance services
        IComplianceService quantumSafeService = new BasicQuantumSafeComplianceService();
        IComplianceService nistService = new NISTSP800131AR3ComplianceService();

        // Register them with identifiers
        services.put("quantum_safe", quantumSafeService);
        services.put("nist_sp_800_131_ar3", nistService);

        // Define the default service
        this.defaultService = quantumSafeService;
    }

    public IComplianceService getService(String policyIdentifier) {
        IComplianceService service = services.get(policyIdentifier);
        if (service == null) {
            service = defaultService;
        }
        return service;
    }

    public void register(String policyIdentifier, IComplianceService service) {
        services.put(policyIdentifier, service);
    }

    public boolean remove(String policyIdentifier) {
        // Prevent deleting built-in policies
        if (policyIdentifier.equals("quantum_safe")
                || policyIdentifier.equals("nist_sp_800_131_ar3")) {
            return false;
        }

        return services.remove(policyIdentifier) != null;
    }

    public List<Map<String, String>> listPolicies() {
        List<Map<String, String>> policyList = new ArrayList<>();
        for (Map.Entry<String, IComplianceService> entry : services.entrySet()) {
            Map<String, String> map = new HashMap<>();
            map.put("id", entry.getKey());
            map.put("label", entry.getValue().getName());
            policyList.add(map);
        }
        return policyList;
    }
}
