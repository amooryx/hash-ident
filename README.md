<div align="center">
  <img src="./banner.svg" alt="hash-ident" width="800">
</div>

# hash-ident

> Suggest likely hash formats from an input string.

`hash-ident` is an offline format-identification helper for authorized security
testing, labs, and research. It does not verify hashes, access systems, crack
values, or provide attack commands.

## Install

```bash
git clone https://github.com/amooryx/hash-ident.git
cd hash-ident
```

Requires Python 3.10 or later; there are no third-party dependencies.

## Usage

```bash
python hash_ident.py '<hash-or-encoded-value>'
```

The tool asks for authorization before processing input. `-y` skips that
confirmation, and `-o FILE` writes a JSON report.

Hexadecimal values are reported as **ambiguous candidates** based on character
set and length alone: many different algorithms produce outputs with the same
length, so this cannot identify the algorithm conclusively. Structured formats
are matched against their prefixes and expected shapes, but should still be
verified independently. Inputs longer than 4,096 characters are rejected.
Unsupported and malformed values are reported as unrecognized rather than
guessed.

## Tests

Run the offline unit tests with:

```bash
python -m unittest discover -s tests -v
```

## Disclaimer

Use this tool only for systems and data you own or have explicit permission to
assess.

## Author

**Omar Khalid** — [omareldemery.com](https://omareldemery.com) | [@amooryx](https://github.com/amooryx)

Certifications: OSCP+ · OSCP · CRTP · eWPTX · eCPPT · eCDFP · eCIR · eJPT
