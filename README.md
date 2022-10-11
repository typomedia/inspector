# Symfony Inspector Command

## Clone

    git clone https://gitlab.com/typomedia/inspector.git
    cd inspector/
    composer install --no-dev

## Download

[inspector.phar](../raw/master/dist/inspector.phar)

## Usage

    bin/inspector check [options] [--] [<name>]

## Arguments
    lockfile                 The path to the composer.lock file [default: "composer.lock"]

## Options
    -s, --severity=SEVERITY  Defines the severity level [default: "low"]
    -w, --whitelist[=WHITELIST]  The path to the whitelist.json file

## Example

    bin/inspector check --severity high example.json

## Help

    bin/inspector check --help

## Format

```json
{
  "packages": [
    {
      "name": "bootstrap",
      "version": "v3.3.7",
      "homepage": "bootstrap.com"
    },
    {
      "name": "twig/twig",
      "version": "v2.14.11",
      "whitelist": [
        "GHSA-52m2-vc4m-jj33",
        "CVE-2022-39261"
      ]
    },
    {
      "name": "dompdf/dompdf",
      "version": "v1.0.2"
    }
  ]
}
```

---
2022 Typomedia Foundation. Created with ♥ in Heidelberg by Philipp Speck.


