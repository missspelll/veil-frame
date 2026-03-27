# veil-frame

veil-frame is a Flask observatory for image steganography.
it lets you hide payloads in one orbit and sweep for hidden signals in another.

the UI uses a custom unicode glyph map for its visual identity — vowels render
in **Mathematical Sans-Serif Bold** and consonants in **Mathematical Sans-Serif**.
the map is defined in `static/app.js` and `static/lite.js` as `unicode_lower`,
applied via `stylizeUi()`. see `docs/unicode-glyph-map.md` for the full table
and rules for contributing text.

## constellation at a glance
- encoder orbits: `simple_lsb`, `advanced_lsb`, `lsb`, `pvd`, `dct`, `f5`, `spread_spectrum`, `palette`, `chroma`, `png_chunks`.
- decoder sweep includes ranked `auto_detect`, method-targeted decoders, bit-plane carving, internal analyzers, and external stego tools.
- profile-driven analysis depth: `quick`, `balanced`, `deep`, `forensic`.
- custom analyzer selection lets you choose exactly which stars to scan.
- `veil-frame-lite` at `/lite` keeps a smaller sky: `simple_lsb` + `advanced_lsb` encode, plus lite decode tools.

## launch sequence (docker compose)
```bash
cd veil-frame
docker compose up --build
```
then open `http://127.0.0.1:5050`.

notes:
- container port `5000` is published to host `5050`.
- the repo is bind-mounted into `/workspace` for fast iteration.
- compose runtime sets `FLASK_ENV=development` and `FLASK_DEBUG=1`.

## devcontainer orbit
1. open the folder in vs code.
2. run "reopen in container".
3. the devcontainer uses the same docker stack, with tooling preinstalled.

## local run (without docker)
install python 3.11+ and the external tools you need (for example: `binwalk`, `foremost`, `steghide`, `outguess`, `zsteg`, `exiftool`, `strings`, `7z`).

```bash
cd veil-frame
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
flask --app app run --debug
```
then open `http://127.0.0.1:5000`.

## production burn (gunicorn)
```bash
pip install -r requirements.txt
gunicorn wsgi:app --bind 0.0.0.0:8000
```

for hosted platforms, bind to `$PORT`:
```bash
gunicorn wsgi:app --bind 0.0.0.0:$PORT
```

the docker image itself starts with:
```bash
gunicorn --bind 0.0.0.0:${PORT:-10000} app:app
```

---

## analysis profiles

the decoder uses four profiles that control which tools run and how deep the analysis goes. the UI auto-selects analyzers and advanced options based on the chosen profile.

### quick (eta: 15s - 1m 30s)
fast, python-only signal checks. no external tools.

**internal analyzers (10):**

| analyzer | description |
|----------|-------------|
| `smart_scan` | quick entropy + format triage to prioritize likely payload paths |
| `advanced_lsb` | per-channel text/zlib detector for multi-plane payloads |
| `simple_lsb` | common lsb text extraction across rgb/rgba planes |
| `simple_zlib` | zlib stream recovery from typical lsb bitstreams |
| `simple_rgb` | rgb plane text extraction |
| `red_plane` | red channel isolated extraction |
| `green_plane` | green channel isolated extraction |
| `blue_plane` | blue channel isolated extraction |
| `alpha_plane` | alpha channel isolated extraction |
| `decode_options` | method-targeted decoders (lsb, pvd, dct, f5, etc.) |

### balanced (eta: 1m - 4m)
everyday workshop profile. broad coverage without deep brute-force passes.

**internal analyzers (18):** all quick analyzers plus:

| analyzer | description |
|----------|-------------|
| `stegg` | legacy stegg-compatible decode probe |
| `zero_width` | zero-width unicode hidden text extraction |
| `entropy_analyzer` | channel entropy anomalies and lsb randomness checks |
| `jpeg_qtable_analyzer` | jpeg quantization table forensic hints |
| `statistical_steg` | statistical detection heuristics for embedded data |
| `payload_unwrap` | unwrap base64/base91/xor/rot payload wrappers |
| `xor_flag_sweep` | keyword-guided xor sweep for ctf-style payloads |
| `randomizer_decode` | shuffle/xor candidate decodes for obfuscated plaintext |
| `decomposer` | render per-plane images for visual payload inspection |

**external tools (19):**

| tool | what it does |
|------|-------------|
| `binwalk` | signature scan for embedded file segments |
| `foremost` | header/footer carving for hidden file recovery |
| `exiftool` | metadata and profile anomaly extraction |
| `strings` | readable byte sequences from carrier file |
| `steghide` | steghide extraction using provided password |
| `zsteg` | png/bmp lsb brute and signature extraction |
| `stegpy` | python stego tool probe |
| `stegolsb` | stego-lsb extraction tool |
| `lsbsteg` | LSB-Steganography tool |
| `stegano_lsb` | stegano lsb extraction |
| `stegano_lsb_set` | stegano lsb-set extraction |
| `stegano_red` | stegano red channel extraction |
| `cloackedpixel` | cloacked-pixel stego tool |
| `cloackedpixel_analyse` | cloacked-pixel analysis mode |
| `stegsnow` | whitespace steganography (snow) |
| `stegify` | go-based image stego tool |
| `openstego` | java-based stego suite |
| `file` | file type detection |
| `7z` | archive extraction |

### deep (eta: 3m - 12m)
adds deep-frequency and plane-carving passes for stronger recovery odds.

**internal analyzers (20):** all balanced analyzers plus:

| analyzer | description |
|----------|-------------|
| `plane_carver` | file signature carving over many bitstream traversals |
| `outguess` | outguess extraction pass with password |

**external tools (35):** all balanced tools plus:

| tool | what it does |
|------|-------------|
| `outguess` | outguess stego extraction with password |
| `stegbreak` | jpeg stego password cracking |
| `stegseek` | steghide seed/password cracking |
| `stegcracker` | steghide password brute-force |
| `fcrackzip` | zip password cracking |
| `stegoveritas` | comprehensive stego analysis suite |
| `bulk_extractor` | bulk data extraction and carving |
| `scalpel` | file carving engine |
| `hideme` | audio/image hiding tool |
| `mp3stego_encode` | mp3 steganography encoder probe |
| `mp3stego_decode` | mp3 steganography decoder probe |
| `jphide` | jpeg hiding tool |
| `jphs` | jpeg seek probe |
| `jpseek` | jpeg stego extraction |
| `stegexpose` | statistical steganalysis |

**auto-enabled options:** spread spectrum decoding, binwalk extraction.

### forensic (eta: 8m - 30m)
maximum depth with manual/interactive tool hooks enabled.

**internal analyzers (20):** same as deep.

**external tools (45):** all deep tools plus:

| tool | what it does |
|------|-------------|
| `openpuff` | gui multi-carrier stego (presence probe) |
| `deepsound` | audio stego gui tool (presence probe) |
| `stegosuite` | java gui stego suite (presence probe) |
| `testdisk` | interactive disk/partition recovery |
| `photorec` | interactive file recovery |
| `wireshark` | network packet analysis |
| `bvi` | binary/hex editor |
| `stegsolve` | visual stego analysis (bit planes, transforms) |
| `qrencode` | qr code generation |
| `sonic_visualiser` | audio spectrum forensics (presence probe) |

**auto-enabled options:** spread spectrum decoding, binwalk extraction, invisible unicode sweep (all tiers, high aggressiveness).

---

## additional tooling in the docker image

the docker image also installs these utilities used by the analyzer pipeline:

| category | tools |
|----------|-------|
| **image metadata** | `identify`, `convert`, `jpeginfo`, `jpegsnoop`, `jhead`, `exiv2`, `exifprobe`, `pngcheck`, `pngtools`, `mediainfo` |
| **image format** | `jpegtran`, `cjpeg`, `djpeg`, `optipng`, `pngcrush`, `jpegdump`, `jpegrescan`, `pngfix`, `gifextract`, `webpinfo`, `webpmux` |
| **detection** | `stegdetect`, `jsteg`, `zbarimg`, `tesseract` |
| **media/audio** | `ffmpeg`, `ffprobe`, `sox` |
| **pdf** | `pdfinfo`, `pdftotext`, `pdfimages`, `qpdf` |
| **binary analysis** | `radare2`, `rizin`, `hexyl`, `xxd`, `rg` |
| **network/disk** | `tshark`, `sleuthkit` (`mmls`), `volatility` |
| **archives** | `tar`, `gzip`, `bzip2`, `unzip`, `unsquashfs`, `xz` |

---

## api star chart

### `POST /api/encode`
form-data fields:
- `image` (required file, png or jpeg, max 8 mb).
- `encodeMethod` one of: `simple_lsb`, `advanced_lsb`, `lsb`, `pvd`, `dct`, `f5`, `spread_spectrum`, `palette`, `chroma`, `png_chunks`.
- `payloadMode`: `text` or `file`.
- `text` payload (when using text mode).
- `payload` file payload (when using file mode).
- `outputFormat`: `png` or `jpeg`.

simple/advanced controls:
- `simple_lsb`: `mode` (`text` or `zlib`), `plane` (`RGB`, `R`, `G`, `B`, `A`, `RGBA`).
- `advanced_lsb`: `channels` json object and optional uploaded files `file_R`, `file_G`, `file_B`, `file_A`.

method option fields:
- `lsbChannels`, `lsbBits`
- `pvdDirection`, `pvdRange`
- `dctRobustness`, `dctBlockSize`
- `f5Password`, `f5Quality`
- `spreadPassword`, `spreadFactor`, `spreadStrength`
- `paletteColors`, `paletteMode`
- `chromaSpace`, `chromaChannel`, `chromaIntensity`, `chromaPattern`
- `pngChunkType`, `pngChunkKeyword`

response: json containing `filename` and `data_url`.

### `POST /api/decode`
form-data fields:
- `image` (required file, max 8 mb)
- `password` (optional)
- `analysisProfile` (`quick`, `balanced`, `deep`, `forensic`)
- `selectedTools` (json array of analyzer ids)
- `spreadSpectrum` (`true`/`false`)
- `binwalkExtract` (`true`/`false`)
- `unicodeSweep` (`true`/`false`)
- `unicodeTier1` (`true`/`false`)
- `unicodeSeparators` (`true`/`false`)
- `unicodeAggressiveness` (`low`, `balanced`, `high`)
- `decodeOption` (`auto_detect`, `lsb`, `pvd`, `dct`, `f5`, `spread_spectrum`, `palette`, `chroma`, `png_chunks`)
- `deep` (`true`/`false`) — legacy override, profile controls this
- `manual` (`true`/`false`) — legacy override, profile controls this

response: analysis json with `results`, optional `artifacts`, and `meta`.

### profile and tooling endpoints
- `GET /api/tools`
- `GET /api/profiles`
- `GET /api/analyzers?profile=<id>`

### lite endpoints
- `GET /lite`
- `GET /api/lite/tools`
- `POST /api/lite/encode` (supports `simple_lsb` and `advanced_lsb` only)
- `POST /api/lite/decode`

lite encode notes:
- `advanced_lsb` in lite outputs png only.
- same 8 mb upload limit applies.

## render deployment stars
### docker service
- create a new render web service with environment set to docker.
- point it to this repository.
- render builds from `Dockerfile` and starts on `0.0.0.0:$PORT`.

### blueprint (`render.yaml`)
- create a render blueprint.
- render reads `render.yaml` and provisions the docker web service.

## smoke verification
inside the running container:
```bash
docker compose exec web bash -lc "which binwalk; which foremost; which steghide; which outguess; which zsteg; which exiftool; which strings; which 7z; which file; which unzip; which unsquashfs"
docker compose exec web make smoke
```

if you are on a restricted runner without the full toolchain:
```bash
ALLOW_MISSING_TOOLS=1 make smoke
```

## troubleshooting under cloud cover
- if the port is busy, change host mapping in `docker-compose.yml`.
- if docker is not running, start docker desktop/daemon first.
- if a tool is missing, the ui marks it missing and continues where possible.
- first docker build is heavy because the image installs broad stego tooling.

## security horizon
do not expose the flask debugger on untrusted networks.
for production, run behind a proper reverse proxy and keep debug mode off.

## twitter note (lsb orbit stability)
the twitter-safe compression guardrail is documented in `docs/twitter-encoding.md`.
short version: the app pre-compresses and, when needed, downscales so png output stays near twitter's recompression threshold.

## license
this repository is released under the mit license (`LICENSE`).
