# Offline workflow viewer

Open **[workflow.html](../../workflow.html)** from the repository root in a browser, or double-click it in the file manager. The generated HTML contains its styles, JavaScript and the entire `workflow.md` guide. It works from `file://` without a server, internet connection or CDN.

The animated examples are simulations. They do not connect to the SOC backend or execute endpoint actions. The viewer includes four scenarios, step selection, playback controls, nine role summaries, the source permission tables, and all 24 searchable guide sections. Reduced-motion preference starts playback paused. Leaving the workflow tab pauses it; a hidden browser tab suspends the timer.

After updating `workflow.md`, regenerate the HTML:

```sh
python3 scripts/generate_workflow_html.py
```

The builder requires Python-Markdown (`python3 -m pip install Markdown`). This is a build dependency only; opening the HTML requires no installation. The complete guide and access matrices are generated from Markdown. Scenario and role summaries are authored in `viewer.js` and should be reviewed if the source workflow changes. The source date is the document date, not a claim about current production state.

Use **Complete guide → Print / Save PDF** to print all guide sections, including sections hidden by a search. Visual source files are `template.html`, `viewer.css`, and `viewer.js`; `workflow.html` is the distributable single-file output.
