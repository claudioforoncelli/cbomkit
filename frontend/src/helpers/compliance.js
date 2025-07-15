import { model } from "@/model.js";
import { getDetections, getLocalComplianceServiceName } from "@/helpers.js";

export const complianceIconMap = {
  CHECKMARK: 'Checkmark24',
  CHECKMARK_SECURE: 'Security24',
  WARNING: 'WarningAlt24',
  ERROR: 'MisuseOutline24',
  NOT_APPLICABLE: 'NotAvailable24',
  UNKNOWN: 'WatsonHealthImageAvailabilityUnavailable24'
};

export function getPolicyResultsByAsset(asset) {
  if (
      asset == null ||
      !Object.hasOwn(asset, "bom-ref") ||
      model.policyCheckResult == null
  ) {
    return [];
  }
  const bomRef = asset["bom-ref"];
  return model.policyCheckResult.findings.filter(f => f["bomRef"] === bomRef);
}

export function getComplianceLevel(asset) {
  if (!hasValidComplianceResults()) return false;
  let status = model.policyCheckResult.defaultComplianceLevel;
  const levels = getPolicyResultsByAsset(asset).map(f => f["levelId"]);
  if (levels.length > 0) status = Math.min(...levels);
  return status;
}

export function getComplianceObjectFromId(id) {
  const levels = getComplianceLevels();
  const res = levels.filter(level => level.id === id);
  if (res.length === 1) return res[0];
  console.error(`No compliance level found for asset with compliance ID ${id}`);
  return null;
}

function getComplianceObject(asset) {
  const id = getComplianceLevel(asset);
  return getComplianceObjectFromId(id);
}

export function getComplianceColor(asset) {
  const obj = getComplianceObject(asset);
  return obj?.colorHex || "#999";
}

export function getComplianceIcon(asset) {
  const obj = getComplianceObject(asset);
  return obj ? complianceIconMap[obj.icon] : complianceIconMap.UNKNOWN;
}

export function getComplianceLabel(asset) {
  return getComplianceObject(asset)?.label || "Unknown";
}

export function getComplianceDescription(asset) {
  const obj = getComplianceObject(asset);
  return obj?.description || obj?.label || "No description";
}

export function getComplianceFindingsWithMessage(asset) {
  if (!hasValidComplianceResults() || asset == null) return [];
  return model.policyCheckResult.findings.filter(
      f => f.message && f.bomRef === asset["bom-ref"]
  );
}

export function isLoadingCompliance() {
  return model.policyCheckResult == null;
}

export function hasValidComplianceResults() {
  const result = model.policyCheckResult;
  return result && result.error === false && typeof result.assessmentLevel === "object";
}

export function getCompliancePolicyName() {
  const selected = model.availablePolicies.find(p => p.id === model.selectedPolicyIdentifier);
  return selected?.label || selected?.id || "Unknown";
}

export function getComplianceServiceName() {
  return hasValidComplianceResults() ? model.policyCheckResult.complianceServiceName : "";
}

export function isUsingLocalComplianceService() {
  return getComplianceServiceName() === getLocalComplianceServiceName();
}

export function getComplianceLevels() {
  return hasValidComplianceResults() ? model.policyCheckResult.complianceLevels : [];
}

export function getAssessmentLevels() {
  return hasValidComplianceResults() && Array.isArray(model.policyCheckResult.assessmentLevels)
      ? model.policyCheckResult.assessmentLevels
      : [];
}

export function checkValidComplianceResults(policyCheckResult) {
  if (!policyCheckResult || policyCheckResult.error !== false) {
    console.error("The compliance backend was not able to return a result:", policyCheckResult);
    return false;
  }

  console.log("Passed: basic existence and error === false. Checking top-level fields...");

  if (
      typeof policyCheckResult.policyName !== 'string' ||
      typeof policyCheckResult.complianceServiceName !== 'string' ||
      !Array.isArray(policyCheckResult.findings) ||
      !Array.isArray(policyCheckResult.complianceLevels) ||
      typeof policyCheckResult.defaultComplianceLevel !== 'number' ||
      typeof policyCheckResult.assessmentLevel !== 'object'
  ) {
    console.error("Invalid top-level structure:");
    console.log("policyName:", typeof policyCheckResult.policyName);
    console.log("complianceServiceName:", typeof policyCheckResult.complianceServiceName);
    console.log("findings (isArray):", Array.isArray(policyCheckResult.findings));
    console.log("complianceLevels (isArray):", Array.isArray(policyCheckResult.complianceLevels));
    console.log("defaultComplianceLevel:", typeof policyCheckResult.defaultComplianceLevel);
    console.log("assessmentLevel:", typeof policyCheckResult.assessmentLevel);
    return false;
  }

  console.log("Passed: top-level structure. Checking complianceLevels...");
  const validLabelIds = new Set();
  for (const level of policyCheckResult.complianceLevels) {
    if (
        typeof level.id !== 'number' ||
        typeof level.label !== 'string' ||
        typeof level.colorHex !== 'string' ||
        typeof level.icon !== 'string'
    ) {
      console.error("Invalid compliance level structure:", level);
      return false;
    }

    if (!Object.keys(complianceIconMap).includes(level.icon)) {
      console.error("Invalid icon:", level.icon, "Expected one of:", Object.keys(complianceIconMap).join(", "));
      return false;
    }

    if (level.description && typeof level.description !== 'string') {
      console.error("Description must be a string (if present):", level);
      return false;
    }

    if (validLabelIds.has(level.id)) {
      console.error("Duplicate compliance level ID:", level.id);
      return false;
    }
    validLabelIds.add(level.id);
  }

  console.log("Passed: complianceLevels. Checking findings...");
  for (const item of policyCheckResult.findings) {
    if (
        typeof item.bomRef !== 'string' ||
        typeof item.levelId !== 'number' ||
        !validLabelIds.has(item.levelId)
    ) {
      console.error("Invalid finding entry:", item);
      return false;
    }

    if (item.message && typeof item.message !== 'string') {
      console.error("Message must be a string (if present):", item);
      return false;
    }
  }

  console.log("Passed: findings. Checking assessmentLevels array if present...");
  if (Array.isArray(policyCheckResult.assessmentLevels)) {
    const validAssessmentIds = new Set();
    for (const al of policyCheckResult.assessmentLevels) {
      if (typeof al.id !== 'number' || typeof al.label !== 'string') {
        console.error("Malformed assessment level:", al);
        return false;
      }
      if (validAssessmentIds.has(al.id)) {
        console.error("Duplicate assessment level ID:", al.id);
        return false;
      }
      validAssessmentIds.add(al.id);
    }
    console.log("Passed: assessmentLevels array.");
  } else {
    console.log("No assessmentLevels array found, skipping validation for it.");
  }

  console.log("Validation successful: checkValidComplianceResults returned true.");
  return true;
}


export function getComplianceRepartition() {
  const detections = getDetections();
  const ids = getComplianceLevels().map(level => level.id);
  const counts = Object.fromEntries(ids.map(id => [id, 0]));

  detections.forEach(det => {
    const status = getComplianceLevel(det);
    if (counts[status] !== undefined) counts[status]++;
  });

  return counts;
}

export function getColorScale() {
  const counts = getComplianceRepartition();
  const levels = getComplianceLevels();
  const colors = Object.fromEntries(levels.map(level => [level.id, level.colorHex]));
  const labels = Object.fromEntries(levels.map(level => [level.id, level.label]));

  const scale = {};
  Object.keys(counts).forEach(id => {
    scale[labels[id]] = colors[id];
  });

  return scale;
}
