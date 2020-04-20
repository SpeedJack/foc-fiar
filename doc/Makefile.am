LATEXMKOPTS = -pdf -cd -use-make -pdflatex="pdflatex -interaction=nonstopmode %O %S"

if BUILD_DOC
EXTRA_DIST = $(srcdir)/*.tex $(srcdir)/*.sty $(srcdir)/**/*.tex \
	$(srcdir)/**/**/*.tex $(srcdir)/**/*.eps

doc_DATA = report.pdf

.PHONY: FORCE_MAKE

report.pdf: $(srcdir)/report.tex FORCE_MAKE
	$(LATEXMK) $(LATEXMKOPTS) $<

clean:
	$(LATEXMK) -C
	${RM} chapters/*.aux report.bbl report.run.xml **/*-converted-to.*
endif
