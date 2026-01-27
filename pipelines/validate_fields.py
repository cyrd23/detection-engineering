name: Validate Detections

on:
  workflow_dispatch:
    inputs:
      all:
        description: "Validate ALL detections (true/false)"
        required: false
        default: "false"
  push:
    branches: [ "main" ]
    paths:
      - "detections/**"
      - "pipelines/**"
      - ".github/workflows/validate.yml"
  pull_request:
    branches: [ "main" ]
    paths:
      - "detections/**"
      - "pipelines/**"
      - ".github/workflows/validate.yml"

jobs:
  validate:
    # IMPORTANT: use the label(s) your self-hosted runner actually has
    runs-on: [self-hosted]

    env:
      # ---- Map your repo secrets to what the scripts expect ----
      KIBANA_URL: ${{ secrets.KIBANA_URL }}
      KIBANA_SPACE: ${{ secrets.KIBANA_SPACE }}

      ELASTIC_URL: ${{ secrets.ELASTICSEARCH_URL }}     # <-- dry_run_detection.py expects ELASTIC_URL
      ELASTIC_API_KEY: ${{ secrets.ELASTIC_API_KEY }}

      ELASTIC_USERNAME: ${{ secrets.ELASTIC_USERNAME }}
      ELASTIC_PASSWORD: ${{ secrets.ELASTIC_PASSWORD }}

      # If your scripts also accept ES_URL, set it too (harmless)
      ES_URL: ${{ secrets.ELASTICSEARCH_URL }}

    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Bootstrap pip + install deps
        run: |
          python -m ensurepip --upgrade
          python -m pip install --upgrade pip
          python -m pip install -r pipelines/requirements.txt

      - name: Determine detection files to validate
        id: files
        shell: bash
        run: |
          set -euo pipefail

          # Manual run can validate everything
          if [[ "${{ github.event_name }}" == "workflow_dispatch" && "${{ github.event.inputs.all }}" == "true" ]]; then
            find detections -type f \( -name "*.yml" -o -name "*.yaml" \) | sort > /tmp/detections.txt
            echo "mode=all" >> "$GITHUB_OUTPUT"
          else
            # PR: diff vs base; Push: diff vs previous commit
            if [[ "${{ github.event_name }}" == "pull_request" ]]; then
              git diff --name-only "origin/${{ github.base_ref }}"...HEAD \
                | grep -E '^detections/.*\.(yml|yaml)$' \
                | sort > /tmp/detections.txt || true
            else
              git diff --name-only HEAD~1...HEAD \
                | grep -E '^detections/.*\.(yml|yaml)$' \
                | sort > /tmp/detections.txt || true
            fi

            # If none changed, exit gracefully
            if [[ ! -s /tmp/detections.txt ]]; then
              echo "No detection files changed."
              echo "mode=none" >> "$GITHUB_OUTPUT"
              exit 0
            fi

            echo "mode=changed" >> "$GITHUB_OUTPUT"
          fi

          echo "Files to validate:"
          cat /tmp/detections.txt

      - name: Validate fields exist in Elasticsearch (staging)
        if: steps.files.outputs.mode != 'none'
        shell: bash
        run: |
          set -euo pipefail
          while IFS= read -r rule; do
            echo "==> Field validation: $rule"
            python pipelines/validate_fields.py \
              --rule "$rule" \
              --es-url "$ELASTIC_URL" \
              --username "$ELASTIC_USERNAME" \
              --password "$ELASTIC_PASSWORD" \
              --api-key "$ELASTIC_API_KEY" \
              --insecure
          done < /tmp/detections.txt

      - name: Dry-run detection queries (staging)
        if: steps.files.outputs.mode != 'none'
        shell: bash
        run: |
          set -euo pipefail
          while IFS= read -r rule; do
            echo "==> Dry-run: $rule"
            python pipelines/dry_run_detection.py \
              --rule "$rule" \
              --es-url "$ELASTIC_URL" \
              --api-key "$ELASTIC_API_KEY" \
              --insecure
          done < /tmp/detections.txt
