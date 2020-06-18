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

If it's the first time, or if any `Makefile.am` or `configure.ac` or any file
under the `m4/` directory has changed, run:

```sh
autoreconf --install
./configure
```

To disable the generation of the PDF, pass the `--disable-latex-doc` option to
the `configure` call above:

```sh
./configure --disable-latex-doc
```

For debugging, use:
```sh
./configure --enable-debug --enable-warnings --enable-assertions
```

When the source is configured, run:

```sh
make
```

Executables will be placed under the `client` and `server` directories. Final
report will be placed in `doc/report.pdf`.

#### VPATH Compile

Alternatively to the above, to avoid to waste the source folder with object
files and binaries:

```sh
autoreconf --install
mkdir build && cd build
../configure
make
```
(`configure` must be run from the `build/` directory)

Note that the report will be generated always in the top level `doc` directory.

#### Clean

To clean the working directory:

```sh
make clean
```

Or, more aggressively:

```sh
make maintainer-clean
```

After a `maintainer-clean` you need to rerun `configure` again to rebuild the
project.
