# nsucurl

`nsucurl` is a curl-compatible wrapper for Akamai NetStorage Usage API requests.
It generates these headers and then sends the request:

- `X-Akamai-ACS-Action`
- `X-Akamai-ACS-Auth-Data`
- `X-Akamai-ACS-Auth-Sign`

## Usage

```sh
nsucurl --acs-account UploadAccountMedia \
  --acs-key "$NETSTORAGE_KEY" \
  --acs-action 'version=1&action=dir&format=xml' \
  https://example-nsu.akamaihd.net/123456/path/
```

With `~/.nsuacsrc`:

```ini
[default]
account = UploadAccountMedia
key = <netstorage-http-api-key>
```

```sh
nsucurl --acs-action 'version=1&action=stat' \
  https://example-nsu.akamaihd.net/123456/path/file.txt
```

Upload example:

```sh
nsucurl -X PUT \
  --acs-action 'version=1&action=upload&md5=<hex>&mtime=1260000000' \
  --data-binary @sweep.m4a \
  https://example-nsu.akamaihd.net/123456/files_baseball/sweep.m4a
```

## Options

`nsucurl` options:

- `--acs-config <file>`: credential file path. Default: `~/.nsuacsrc`
- `--acs-section <name>`: credential section. Default: `default`
- `--acs-account <upload-account-id>`
- `--acs-key <key>`
- `--acs-action <query-string>`
- `--acs-sign-version <3|4|5>`: default `5`

Environment variables:

```sh
NETSTORAGE_ACCOUNT=UploadAccountMedia
NETSTORAGE_KEY=...
NETSTORAGE_SECTION=default
NETSTORAGE_CONFIG=~/.nsuacsrc
```
