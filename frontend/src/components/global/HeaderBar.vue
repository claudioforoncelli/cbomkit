<template>
  <cv-header aria-label="Carbon header">
    <cv-header-name
        href="https://research.ibm.com"
        prefix="IBM"
        target="_blank"
    >
      Research
    </cv-header-name>

    <template v-slot:header-global>
      <h4 style="margin: auto 0px auto -25px; color: white">|</h4>
      <span style="margin: auto auto auto 8px; color: white">
        {{ getTitle }}
      </span>

      <!-- Right-aligned wrapper for dropdown and theme button -->
      <div style="display: flex; align-items: center; margin-left: auto;">
        <cv-select
            label="Select a policy"
            hideLabel
            v-model="model.selectedPolicyIdentifier"
            class="custom-dark-dropdown"
            style="margin-right: 16px; display: inline-flex; width: auto; vertical-align: middle;"
        >
          <cv-select-option
              v-for="policy in model.availablePolicies"
              :key="policy.id"
              :value="policy.id"
          >
            {{ policy.label }}
          </cv-select-option>
        </cv-select>

        <cv-header-global-action
            @click="updateTheme"
            :label="tipText"
            tipPosition="bottom"
            tipAlignment="end"
        >
          <BrightnessContrast24 v-if="renderedTheme == 'auto'" />
          <Awake24 v-if="renderedTheme == 'light'" />
          <Moon24 v-if="renderedTheme == 'dark'" />
        </cv-header-global-action>
      </div>
    </template>
  </cv-header>
</template>

<script>
import { model } from "@/model.js";
import { getTitle } from "@/helpers.js";
import { Awake24, Moon24, BrightnessContrast24 } from "@carbon/icons-vue";
import {
  CvSelect,
  CvSelectOption,
  CvHeader,
  CvHeaderName,
  CvHeaderGlobalAction,
} from "@carbon/vue";

export default {
  name: "HeaderBar",
  data() {
    return {
      model,
      renderedTheme: "auto",
      isDarkModeOS: false,
    };
  },
  components: {
    Awake24,
    Moon24,
    BrightnessContrast24,
    CvSelect,
    CvSelectOption,
    CvHeader,
    CvHeaderName,
    CvHeaderGlobalAction,
  },
  computed: {
    getTitle,
    tipText() {
      if (this.renderedTheme == "auto") return "System theme";
      if (this.renderedTheme == "light") return "Light theme";
      if (this.renderedTheme == "dark") return "Dark theme";
      return "";
    },
  },
  methods: {
    updateTheme() {
      if (this.renderedTheme === "auto") {
        this.renderedTheme = "light";
        model.useDarkMode = false;
      } else if (this.renderedTheme === "light") {
        this.renderedTheme = "dark";
        model.useDarkMode = true;
      } else {
        this.renderedTheme = "auto";
        model.useDarkMode = this.isDarkModeOS;
      }
    },
  },
  async mounted() {
    const darkModeMediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
    const darkModeChanged = (e) => {
      this.isDarkModeOS = e.matches;
      if (this.renderedTheme === "auto") {
        model.useDarkMode = e.matches;
      }
    };
    darkModeMediaQuery.addEventListener("change", darkModeChanged);
    this.isDarkModeOS = darkModeMediaQuery.matches;
    model.useDarkMode = this.isDarkModeOS;

    if (model.availablePolicies.length === 0 && typeof model.reloadPolicyIdentifiers === "function") {
      await model.reloadPolicyIdentifiers();
    }
  },
};
</script>

<style>
.custom-dark-dropdown {
  max-width: 100%;
}

.custom-dark-dropdown .bx--select {
  width: auto;
}

.custom-dark-dropdown .bx--select-input {
  background-color: #1f1f1f;
  color: white;
  border: 1px solid #444;
  min-width: unset;
  width: auto;
  padding-right: 2rem; /* space for dropdown arrow */
  white-space: nowrap;
}

.custom-dark-dropdown .bx--select__arrow {
  fill: white;
}
</style>
