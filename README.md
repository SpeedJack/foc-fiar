# Fondations of Cybersecurity - Four-In-A-Row

This project implements the game **Connect 4** (Four-In-A-Row) Online.

Developed for the course of **Foundations of Cybersecurity** of the University of
Pisa.

### Prerequisites

- git (of course!)
- GNU Autotools (usually preinstalled)
- GCC (or MinGW for Windows)
- OpenSSL
- LaTeX (TeX-Live for Unix/Win; MacTeX for OS X)

### Compile

If it's the first time run `autoreconf --install`, then:

```sh
./configure
make
```

Or, to avoid to waste the source folder with object files and binaries:

```sh
mkdir build && cd build
../configure
make
```

Executables will be placed under the `client` and `server` directories.

### Documentation

```sh
cd doc
pdflatex report.tex
```

Rerun `pdflatex` as needed (check output).
