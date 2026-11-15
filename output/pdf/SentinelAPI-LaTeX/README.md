# SentinelAPI LaTeX report

Upload `SentinelAPI_LaTeX_Source.zip` to Overleaf as a new project. Select **XeLaTeX** as the compiler and **main.tex** as the main document, then click **Recompile**.

To build locally from this directory:

```bash
latexmk -xelatex main.tex
```

The source uses the standard LaTeX report class and includes both images under `assets/`. The course, supervisor, department, academic year, and team details are defined near the top of `main.tex`. The certificate has blank fields for the group number, date, and supervisor's signature.

The delivered report was compiled with Tectonic and verified at 40 US Letter pages. The cover has no printed page number, the front matter uses Roman numerals, and Chapter 1 begins at Arabic page 1.
