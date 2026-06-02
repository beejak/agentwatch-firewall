# Makefile for WatchTower IEEE S&P 2027 paper
# Builds watchtower.pdf using pdflatex + bibtex

PAPER    := watchtower
LATEX    := pdflatex
BIBTEX   := bibtex
LATEXFLAGS := -interaction=nonstopmode -halt-on-error

.PHONY: all pdf clean distclean

all: pdf

pdf: $(PAPER).pdf

$(PAPER).pdf: $(PAPER).tex references.bib
	$(LATEX) $(LATEXFLAGS) $(PAPER)
	$(BIBTEX) $(PAPER)
	$(LATEX) $(LATEXFLAGS) $(PAPER)
	$(LATEX) $(LATEXFLAGS) $(PAPER)

clean:
	rm -f $(PAPER).aux $(PAPER).bbl $(PAPER).blg \
	      $(PAPER).log $(PAPER).out $(PAPER).toc \
	      $(PAPER).lof $(PAPER).lot $(PAPER).fls \
	      $(PAPER).fdb_latexmk texput.log

distclean: clean
	rm -f $(PAPER).pdf
