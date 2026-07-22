# Local PDF helper. Submission source is tracewall.tex — NOT watchtower.tex.
PAPER = tracewall
LATEX = pdflatex
BIBTEX = bibtex

.PHONY: all clean view tectonic

all: $(PAPER).pdf

$(PAPER).pdf: $(PAPER).tex
	$(LATEX) $(PAPER)
	$(LATEX) $(PAPER)

# Prefer tectonic when available (Windows: %TEMP%\tectonic-bin\tectonic.exe).
tectonic:
	tectonic -X compile $(PAPER).tex

clean:
	rm -f $(PAPER).aux $(PAPER).bbl $(PAPER).blg $(PAPER).log \
	       $(PAPER).out $(PAPER).toc $(PAPER).fls $(PAPER).fdb_latexmk \
	       $(PAPER).synctex.gz

distclean: clean
	rm -f $(PAPER).pdf

view: $(PAPER).pdf
	xdg-open $(PAPER).pdf 2>/dev/null || open $(PAPER).pdf 2>/dev/null || true
