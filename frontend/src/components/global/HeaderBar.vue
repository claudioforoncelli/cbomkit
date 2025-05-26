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

      <!-- Updated dropdown to use availablePolicies -->
      <select v-model="model.selectedPolicyIdentifier" style="margin-left: 16px;">
        <option
            v-for="policy in model.availablePolicies"
            :key="policy.id"
            :value="policy.id"
        >
          {{ policy.label }}
        </option>
      </select>

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
    </template>
  </cv-header>
</template>

<script>
import { model } from "@/model.js";
import { getTitle } from "@/helpers.js";
import { Awake24, Moon24, BrightnessContrast24 } from "@carbon/icons-vue";

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
    // Theme handling
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

    // ✅ Load policy list if not loaded yet
    if (model.availablePolicies.length === 0 && typeof model.reloadPolicyIdentifiers === "function") {
      await model.reloadPolicyIdentifiers();
    }
  },
};
</script>
