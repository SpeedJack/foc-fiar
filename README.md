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

Executables will be placed under the `client` and `server` directories. Final
report will be placed in `doc/report.pdf`. Note that the report will be
generated always in the top level `doc` directory.

To disable the generation of the PDF, pass the `--disable-latex-doc` option to
the `configure` call above.

To clean the working directory:

```sh
make clean
```
Or, more aggressively:

```sh
make maintainer-clean
```
