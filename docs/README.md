# docs

- `PromptRed_Report.docx`: the End-of-Course Project trade-off analysis. `report_source/build_report.js` regenerates it (`npm install docx`, then `node build_report.js out.docx`).
- `PRODUCT.md`: product documentation: persona, input, output, architecture, and metrics targeted vs reached.
- `PromptRed_PRD_v1.0.docx`: the **original, pre-review** product requirements document, kept for history. The reviews corrected several of its claims, and the report and top-level README supersede them:
  - "There is no systematic, automated tool…": false. promptfoo, NVIDIA garak and Microsoft PyRIT exist. PromptRed's gap is a measured judge and support-bot business-risk scoring.
  - The target "recall ≥ 70% with a false-negative rate of 0%" contradicts itself (recall 70% means a 30% false-negative rate). It is replaced by judge precision, recall and F1 against hand labels, beside two baselines.
  - HarmBench and JailbreakChat as attack sources: replaced by Lakera's Gandalf dataset (MIT licence), cited real incidents and the attack taxonomy.
  - FR-08 ChromaDB attack memory: cut.
