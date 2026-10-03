# AJNAT SOC brochure

Deliverables in the repository root:

- `AJNAT_SOC_Brochure_Improved.pptx`: 12 editable slides, 16:9 format.
- `AJNAT_SOC_Brochure_Improved.pdf`: matching PDF for viewing and sharing.

The original `AJNAT_SOC_Brochure.pptx` is preserved. The new deck follows its
visibility → investigation → response narrative and adds module definitions,
actual UI screenshots, a short incident scenario and Hinglish speaker notes.

Text, diagrams, comparison rows and annotations are native PowerPoint objects.
Screenshots are embedded PNG images. The font is Lato; PowerPoint can substitute
a local font if Lato is unavailable. Notes are also provided in
`Presenter_Notes.md`.

## Screenshot provenance

Images were captured from this repository's React frontend, running locally.
Browser-intercepted sample API responses populate the screens; no production
backend, real customer telemetry, account credentials or response actions were
used. Every screenshot slide is visibly labelled **ACTUAL AJNAT UI / SAMPLE
DATA**. Counts, scores and timings are illustrative, not measurements of product
performance. Crops focus on relevant panels without redrawing the product UI.

| Image | Product component |
| --- | --- |
| SOC overview | `company/src/pages/analyst/soc/RoleDashboardPage.jsx` |
| Endpoint monitoring | `company/src/pages/EDRPage.jsx` |
| Event correlation | `company/src/pages/CorrelationPage.jsx` |
| Investigation | `company/src/pages/ThreatInvestigationPage.jsx` |
| SOAR | `company/src/pages/SoarPage.jsx` |

`assets/` contains the screenshots and capture manifest. `preview/overview.png`
is a contact sheet of all slides. Content is based on the original brochure,
the component implementations above and the product documentation in `docs/`.

## Regeneration

Python dependencies: `python-pptx`, `Pillow`, `playwright`, `cryptography`.
`pypdfium2` is used only for PDF rendering and validation.

1. Install frontend dependencies with `npm ci` in `company/`.
2. Start the frontend on local port 3000 with `npm run dev` in `company/`.
3. Run `python docs/brochure/capture_ui.py` from the repository root.
4. Run `python docs/brochure/build_brochure.py`.
5. Export the PPTX to PDF with PowerPoint or LibreOffice.

The capture script expects Chromium at `/usr/bin/chromium`; adjust the
`executable_path` if using a different installation.

Validation: 12 slides and 12 PDF pages; all slides have speaker notes; all native
text is present in the PDF; no objects extend outside slide boundaries; PPTX ZIP
integrity passes. The rendered slides were visually reviewed.
