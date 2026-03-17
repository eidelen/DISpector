# DISpector

`DISpector` is a small Python/Qt application for inspecting live DIS traffic with `open-dis`.

## Features

- listen for UDP DIS traffic on a host/port
- live packet list with filters for:
  - PDU type
  - entity name
  - application ID
- detailed inspection of the selected PDU
- raw decoded JSON view plus packet bytes in hex

## Install

```powershell
python -m venv .venv
. .\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Run

```powershell
python .\dispector.py
```

## Notes

- default listen host is `0.0.0.0`
- default listen port is `3000`
- `open-dis` is installed from PyPI as the `opendis` package
