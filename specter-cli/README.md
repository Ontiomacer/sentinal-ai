# Specter CLI

Specter is the Sentinel AI forensic operations terminal. It does not duplicate malware analysis logic and does not talk to Ghidra directly. Every operation goes through the existing FastAPI backend.

## Install

```powershell
cd C:\fraud-apk-analyzer
python -m pip install -r specter-cli\requirements.txt
```

## Run

```powershell
python specter-cli\cli.py status
python specter-cli\cli.py cases list
python specter-cli\cli.py cases open CASE-4E9D45B1
python specter-cli\cli.py analyze .\storage\cases\CASE-4E9D45B1\evidence\20260603_062519_AndroGoat.apk --case CASE-4E9D45B1 --ai --watch
python specter-cli\cli.py ghidra functions CASE-4E9D45B1
python specter-cli\cli.py ghidra decompile CASE-4E9D45B1 createIntent
python specter-cli\cli.py report generate CASE-4E9D45B1 --type executive
python specter-cli\cli.py iocs list CASE-4E9D45B1
python specter-cli\cli.py triage inventory --case CASE-4E9D45B1
python specter-cli\cli.py live
```

On Windows, the root `specter.bat` wrapper lets you run:

```powershell
.\specter.bat status
```

## Configuration

Specter reads `specter-cli/config/specter.toml`.

Environment variables override the file:

- `SPECTER_BACKEND_URL`
- `SPECTER_TOKEN`
- `SPECTER_ACTIVE_CASE`
- `SPECTER_TIMEOUT`
- `SPECTER_RETRIES`

## Command Families

- `cases`: list, create, open, status, delete
- `analyze`: upload evidence or legacy APK scan, trigger backend analysis
- `ghidra`: health, functions, imports, exports, classes, strings, decompile, disasm placeholder
- `neural`: summary, score, explain, attack-map
- `report`: generate, inventory, export
- `iocs`: list, export, domains, ips
- `triage`: drives, ingest, inventory, hash
- `live`: interactive forensic shell

Commands support `--json` for automation where practical.
