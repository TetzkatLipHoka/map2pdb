# map2pdb — Erweiterung: eingebettete Debug-Info (JEDI/JCL & madExcept)

Ergänzt map2pdb um das Lesen von Debug-Info **direkt aus kompilierten PE-Images**
(.exe/.dll/.bpl, Win32 **und** Win64) sowie aus den zugehörigen Standalone-Dateien.
Damit lässt sich Delphi-Code von **D7 bis D13** in VTune / WPA / Superluminal
profilen, ohne eine separate .map bereitzustellen.

## Neue Units

| Unit | Zweck |
|------|-------|
| `debug.info.reader.pe.pas`        | PE-Container: parst DOS/NT-Header (32/64), Sections und Resource-Directory. Findet die `JCLDEBUG`-Section oder die `MAD`/`EXCEPT`-Resource und delegiert. |
| `debug.info.reader.madexcept.pas` | Clean-room-Decoder für den madExcept-Map-Blob: Blowfish-Entschlüsselung (Standard-π-Konstanten, madExcept-„old"-Blocklayout) → raw-DEFLATE (`System.ZLib`) → Delta-kodiertes Binärformat. Keine `mad*`-Abhängigkeiten, MPL-2.0-sauber. |

Die eingebettete `JCLDEBUG`-Section ist byte-identisch zum Standalone-`.jdbg`-Format
und wird an den vorhandenen `TDebugInfoJdbgReader` weitergereicht.

## Unterstützte Eingabeformate

| Format | Erkennung | Reader |
|--------|-----------|--------|
| `.map`             | Delphi Detailed-MAP (Standalone)      | vorhanden |
| `.jdbg`            | JEDI/JCL Standalone                    | vorhanden |
| `.mad`             | madExcept Standalone-Blob (NEU)        | `madexcept` |
| `.exe/.dll/.bpl`   | eingebettet: JCLDEBUG **oder** madExcept (NEU) | `pe` → `jdbg`/`madexcept` |

Erzwingen per `-format:map|jdbg|pe|mad`.

## Verwendung

```
:: CPU-Profiling-Workflow für eine bestehende Exe mit eingebetteter Debug-Info
map2pdb myapp.exe -bind        :: erzeugt myapp.pdb und patcht myapp.exe darauf
:: danach myapp.exe in VTune / WPA / Superluminal öffnen

:: Standalone-madExcept-Blob inspizieren
map2pdb dump.mad -yaml:dump.yaml
```

## Build

`map2pdb.dpr` mit Delphi 10.3+ kompilieren (getestet mit 12.3 / 13.1). Die neuen
Units hängen nur an der RTL (`Winapi.Windows`, `System.ZLib`, `System.SysUtils`).

## Validierung (End-to-End getestet)

Adressgenauer Abgleich madExcept ↔ JCL für dieselbe Binary (identische RVAs), über:

- Win32 **und** Win64
- Delphi 7 **und** Delphi 12.3
- eingebettete JCLDEBUG-Section, eingebettete madExcept-Resource, Standalone `.mad`/`.jdbg`
- PDB-Erzeugung + `-bind`

## Grenzen

- madExcept-„MinDebugInfo"-Blobs (ohne Symbolnamen) werden bewusst abgelehnt.
- Zeilen werden pro Unit einer synthetischen Quelldatei `<Unit>.pas` zugeordnet
  (madExcept speichert keine separaten Dateinamen).
