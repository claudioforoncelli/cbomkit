<template>
  <div>
    <!-- Scanning loader -->
    <LoaderView
        v-if="model.scanning.isScanning"
        class="skeleton-bordered"
        :style="{ borderColor: skeletonColor, marginRight: 'auto', paddingLeft: '16px', display: 'flex', alignItems: 'center' }"
    />

    <!-- Skeleton inline notification -->
    <div
        class="skeleton-bordered"
        v-else-if="isLoadingCompliance"
        :style="{ borderColor: skeletonColor }"
    >
      <InProgress16
          style="margin: 0px 16px 0px 6px"
          :style="{ color: skeletonColor }"
      />
      <h6 style="padding: 7px 12px 7px 0px">Analyzing compliance...</h6>
      <cv-skeleton-text
          :heading="false"
          :paragraph="false"
          :line-count="1"
          style="margin-bottom: -8px; width: 60%"
      />
    </div>

    <!-- Inline notification -->
    <cv-inline-notification
        v-else
        :kind="kind"
        :title="title"
        :sub-title="description"
        :low-contrast="true"
        :hide-close-button="true"
        style="margin: 0px"
        :style="{ background: backgroundColor }"
    />
  </div>
</template>

<script>
import { model } from "@/model.js";
import {
  getComplianceReport,
  isLoadingCompliance,
  hasValidComplianceResults,
  getCompliancePolicyName,
  getComplianceServiceName
} from "@/helpers";
import { InProgress16 } from "@carbon/icons-vue";
import LoaderView from "@/components/results/LoaderView.vue";

export default {
  name: "RegulatorResults",
  data() {
    return { model };
  },
  components: {
    InProgress16,
    LoaderView,
  },
  computed: {
    isLoadingCompliance,
    complianceResult() {
      return model.policyCheckResult;
    },
    title() {
      if (this.isLoadingCompliance) return "Analyzing compliance...";
      if (hasValidComplianceResults()) {
        const label = this.complianceResult?.severityStatus?.label;
        return label ? label.toUpperCase() : "UNKNOWN";
      }
      return "COMPLIANCE RESULTS UNAVAILABLE –";
    },
    description() {
      const policy = getCompliancePolicyName();
      const service = getComplianceServiceName();
      let sourceString = "";
      if (service !== "") {
        sourceString = `<br/><span style="font-size: x-small;">Source: ${service}</span>`;
      }

      if (this.isLoadingCompliance) return "";

      if (hasValidComplianceResults()) {
        const label = this.complianceResult?.severityStatus?.label?.toUpperCase();
        return `CBOM compliance result with respect to policy ${policy}: ${label}.` + sourceString;
      }

      return `Compliance could not be assessed at this time.` + sourceString;
    },
    backgroundColor() {
      if (model.useDarkMode && !this.isLoadingCompliance) {
        if (!hasValidComplianceResults()) return "#2f4c78";
        return "#393939"; // Single color used for all severity levels for now
      }
      return "";
    },
    skeletonColor() {
      return model.useDarkMode ? "#929191" : "#BAB9B9";
    },
    kind() {
      if (!hasValidComplianceResults()) return "info";

      const label = this.complianceResult?.severityStatus?.label?.toLowerCase();
      if (label === "compliant") return "success";
      if (label === "not compliant") return "warning";
      if (label === "potentially compliant") return "warning";
      return "info";
    },
  },
  beforeMount() {
    if (model.cbom != null) {
      getComplianceReport(model.cbom, model.selectedPolicyIdentifier);
    }
  },
  watch: {
    "model.cbom": function (newResult) {
      if (newResult != null) {
        getComplianceReport(model.cbom, model.selectedPolicyIdentifier);
      }
    },
  },
};
</script>

<style scoped>
.skeleton-bordered {
  padding: 7px;
  border-style: solid;
  border-width: thin;
  border-color: lightgray;
  border-left-width: medium;
  display: flex;
  align-items: center;
}
</style>

<style>
.bx--inline-notification {
  max-width: none !important;
}
</style>
