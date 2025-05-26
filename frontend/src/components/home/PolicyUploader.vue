<template>
  <div>
    <cv-file-uploader
        style="margin-top: -24px;"
        ref="policyUploader"
        v-model="uploadedFiles"
        @change="loadFiles"
        kind="drag-target"
        accept=".toml"
        :clear-on-reselect="true"
        :initial-state-uploading="true"
        :multiple="false"
        :removable="true"
    >
      <template #drop-target>
        <div class="drop-container">
          <div class="description-container">
            <div class="description-header">
              <CloudUpload24 style="margin-right: 8px" />
              <div>{{ title }}</div>
            </div>
            <div class="description-subheader">{{ subtitle }}</div>
          </div>
        </div>
      </template>
    </cv-file-uploader>

    <p v-if="message" :class="{ success: isSuccess, error: !isSuccess }">
      {{ message }}
    </p>
  </div>
</template>

<script>
import { CloudUpload24 } from "@carbon/icons-vue";

export default {
  name: "PolicyUploader",
  data() {
    return {
      uploadedFiles: [],
      message: null,
      isSuccess: false,
    };
  },
  components: {
    CloudUpload24,
  },
  computed: {
    title() {
      return "Drop a TOML policy file to upload";
    },
    subtitle() {
      return "(or click to browse)";
    },
  },
  methods: {
    loadFiles(filesInfo) {
      if (filesInfo.length === 2 && filesInfo[0].state === "") {
        this.uploadedFiles.shift(); // Replace invalid file
      }

      const file = this.uploadedFiles[0]?.file;
      if (!file) return;

      const reader = new FileReader();
      reader.onload = () => this.uploadPolicy(file);
      reader.readAsText(file);
    },
    async uploadPolicy(file) {
      const formData = new FormData();
      formData.append("file", file);

      try {
        const response = await fetch("/api/v1/compliance/upload-policy", {
          method: "POST",
          body: formData,
        });

        const result = await response.text();
        this.isSuccess = response.ok;
        this.message = result;

        if (response.ok) {
          this.$refs.policyUploader.setState(0, "complete");
          this.$emit("policy-uploaded");
        } else {
          this.$refs.policyUploader.setInvalidMessage(0, result);
          this.$refs.policyUploader.setState(0, "");
        }
      } catch (e) {
        this.message = "Upload failed. Check the backend.";
        this.isSuccess = false;
        this.$refs.policyUploader.setInvalidMessage(0, "Upload failed");
        this.$refs.policyUploader.setState(0, "");
        console.error(e);
      }
    },
  },
};
</script>

<style scoped>
.drop-container {
  display: flex;
  min-height: 120px;
  margin: auto;
}

.description-container {
  margin: auto;
  display: flex;
  flex-direction: column;
  align-items: center;
}

.description-header {
  display: flex;
  align-items: center;
  font-size: large;
  font-weight: 400;
}

.description-subheader {
  font-size: small;
  font-weight: 400;
  margin-top: 4px;
}

.success {
  color: green;
  padding-top: 0.5em;
}
.error {
  color: red;
  padding-top: 0.5em;
}
</style>

<style>
.bx--file-browse-btn {
  max-width: none !important;
}
.bx--file__drop-container {
  height: auto !important;
  background-color: var(--cds-layer);
}
</style>
