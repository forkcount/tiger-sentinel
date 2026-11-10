name: Tiger Sentinel

on:
  schedule:
    - cron: '0 */6 * * *'   # every 6 hours (00:00, 06:00, 12:00, 18:00 UTC)
  workflow_dispatch:         # manual trigger from the Actions tab

jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 350
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Run Tiger Sentinel
        run: python bot.py
      - name: Commit findings
        if: always()
        run: |
          git config user.name "tiger-sentinel"
          git config user.email "sentinel@users.noreply.github.com"
          git add sentinel_state.json findings_report.json findings_review.json || true
          git diff --staged --quiet || git commit -m "sentinel: scan $(date -u +%Y-%m-%d-%H)"
          git push || echo "push failed"
      - name: Upload artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: findings-${{ github.run_number }}
          path: |
            findings_report.json
            findings_review.json
          retention-days: 30
