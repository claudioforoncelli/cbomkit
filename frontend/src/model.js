import { reactive } from "vue";

export const model = reactive({
  // STATE
  useDarkMode: false,
  showResults: false,
  showDebugging: false,
  cbom: null,
  dependencies: null,
  availablePolicies: [],
  scanning: {
    isScanning: false,
    scanningStatus: null,
    scanningStatusMessage: null,
    scanningStatusError: null,
    liveDetections: [],
    socket: null,
    numberOfFiles: null,
    numberOfLines: null,
    startTime: null,
    scanDuration: null,
    totalDuration: null,
  },
  codeOrigin: {
    projectIdentifier: null,
    scanUrl: null,
    gitUrl: null,
    revision: null,
    subfolder: null,
    commitID: null,
    uploadedFileName: null,
  },
  credentials: {
    username: null,
    password: null,
    pat: null,
  },
  selectedPolicyIdentifier: 'quantum_safe',
  policyCheckResult: null,
  errors: [],
  lastCboms: [],

  // METHODS
  startAgain() {
    this.resetScanningInfo();
    this.resetCodeOriginInfo();
    this.policyCheckResult = null;
    model.showResults = false;
  },
  resetScanningInfo() {
    model.scanning.isScanning = false;
    model.scanning.scanningStatus = null;
    model.scanning.scanningStatusMessage = null;
    model.scanning.scanningStatusError = null;
    model.scanning.liveDetections = [];
    model.scanning.socket = null;
    model.scanning.numberOfFiles = null;
    model.scanning.numberOfFiles = null;
    model.scanning.startTime = null;
    model.scanning.scanDuration = null;
    model.scanning.totalDuration = null;
    model.codeOrigin.commitID = null;
    model.cbom = null;
    model.dependencies = null;
  },
  resetCodeOriginInfo() {
    model.codeOrigin.projectIdentifier = null;
    model.codeOrigin.scanUrl = null;
    model.codeOrigin.gitUrl = null;
    model.codeOrigin.revision = null;
    model.codeOrigin.subfolder = null;
    model.codeOrigin.commitID = null;
    model.codeOrigin.uploadedFileName = null;
  },
  resetCredentials() {
    model.credentials.username = null;
    model.credentials.password = null;
    model.credentials.pat = null;
  },
  addError(errorStatus, message) {
    this.errors.push({ status: errorStatus, message: message });
  },
  closeError(index) {
    this.errors.splice(index, 1);
  },

  // Load compliance policy identifiers from the backend
  async reloadPolicyIdentifiers() {
    try {
      const response = await fetch("/api/v1/compliance/policies");
      if (!response.ok) throw new Error("Failed to load policies");
      const data = await response.json();
      model.availablePolicies = data;

      // Automatically select the first one if current selected is not found
      const match = data.find(p => p.id === model.selectedPolicyIdentifier);
      if (!match && data.length > 0) {
        model.selectedPolicyIdentifier = data[0].id;
      }
    } catch (err) {
      console.error("Error loading compliance policies:", err);
      model.addError(ErrorStatus.NoConnection, "Could not load compliance policies");
    }
  },

  async recheckCompliance() {
    if (!this.cbom || !this.selectedPolicyIdentifier) return;

    try {
      const response = await fetch(
          `/api/v1/compliance/check?policyIdentifier=${this.selectedPolicyIdentifier}`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify(this.cbom),
          }
      );

      const result = await response.json();
      this.policyCheckResult = result;
      this.showResults = true;
    } catch (err) {
      console.error("Failed to recheck compliance:", err);
      this.addError("ScanError", "Failed to recheck compliance with new policy.");
    }
  },

});

export const ErrorStatus = {
  NoConnection: "NoConnection",
  InvalidRepo: "InvalidRepo",
  ScanError: "ScanError",
  JsonParsing: "JsonParsing",
  InvalidCbom: "InvalidCbom",
  IgnoredComponent: "IgnoredComponent",
  MultiUpload: "MultiUpload",
  EmptyDatabase: "EmptyDatabase",
  FallBackLocalComplianceReport: "FallBackLocalComplianceReport",
  ScanWarning: "ScanWarning",
};
