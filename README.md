[![PyPI version](https://img.shields.io/pypi/v/drheaderplus.svg)](https://pypi.org/project/drheaderplus/)
[![PyPI downloads](https://img.shields.io/pypi/dm/drheaderplus.svg)](https://pypi.org/project/drheaderplus/)
[![MIT license](https://img.shields.io/badge/license-MIT-brightgreen.svg)](https://opensource.org/licenses/MIT)

# DrHeaderPlus

There are a number of HTTP headers which enhance the security of a website when used. Often ignored, or unknown, these HTTP security headers help prevent common web application vulnerabilities when used.

DrHeaderPlus helps with the audit of security headers received in response to a single request or a list of requests.

DrHeaderPlus ships a built-in [OWASP ASVS 4.0 V14](https://github.com/OWASP/ASVS/blob/master/4.0/en/0x22-V14-Config.md) preset (`--preset owasp-asvs-v14`) for compliance scanning, and is a useful tool to include as part of an automated CI/CD pipeline which checks for missing HTTP headers.

> DrHeaderPlus is a modernized fork of the original [drHEADer](https://github.com/Santandersecurityresearch/DrHeader) project by Santander UK Security Engineering.

## Features

- **Comprehensive header audit** against a configurable YAML ruleset aligned with OWASP and Mozilla Observatory
- **CSP intelligence** — nonce/hash-aware validation that avoids false positives for modern CSP policies; `strict-dynamic` support
- **CORS misconfiguration detection** — active origin reflection probe in scan mode
- **Cookie security** — `SameSite=None` without `Secure` flag detection, attribute enforcement
- **Leak header detection** — flags `Server`, `X-Powered-By`, `X-AspNet-Version`, and other information disclosure headers
- **Cross-origin isolation** — opt-in COEP/COOP validation for sites that need `SharedArrayBuffer` / high-resolution timers
- **OWASP ASVS 4.0 V14 preset** — built-in `--preset owasp-asvs-v14` for compliance scanning against ASVS configuration requirements
- **Threshold checks** — `Value-Gte` validation for numeric directives (e.g. HSTS `max-age >= 6 months`)
- **Per-rule severity** — high / medium / low aligned with OWASP guidance
- **CLI and library** — use from the command line or integrate into your Python project
- **Multiple output formats** — table, JSON, and JUnit XML for CI/CD integration

## Installation

Requires Python 3.12+. Install from PyPI:

```sh
pip install drheaderplus
```

## How Do I Use It?

There are two ways you could use DrHeaderPlus, depending on what you want to achieve. The easiest way is using the CLI.

### CLI
For details on using the CLI, see [CLI.md](CLI.md)

### In a Project
It is also possible to call DrHeaderPlus from within an existing project, and this is achieved like so:

```python
from drheader import Drheader

scanner = Drheader(headers={'X-XSS-Protection': '1; mode=block'})

report = scanner.analyze()
```

#### Customize HTTP request
By default, the tool uses **HEAD** method when making a request, but you can change that by supplying the `method` argument like this:

```python
from drheader import Drheader

scanner = Drheader(url='https://example.com', method='POST')
```

##### Other `requests` arguments
You can use any other arguments that are supported by `requests` to customise the HTTP request:

```python
from drheader import Drheader

scanner = Drheader(url='https://example.com', headers={'X-API-Key': '726204fe-8a3a-4478-ae8f-4fb216a8c4ba'})
```

```python
from drheader import Drheader

scanner = Drheader(url='https://example.com', verify=False)
```

#### Cross-Origin Isolation
The default rules in DrHeaderPlus support cross-origin isolation via the `Cross-Origin-Embedder-Policy` and
`Cross-Origin-Opener-Policy` headers. Due to the potential for this to break websites that have not yet properly
configured their sub-resources for cross-origin isolation, these validations are opt-in at analysis time. If you want to
enforce these cross-origin isolation validations, you must pass the `cross_origin_isolated` flag.

In a project:
```python
from drheader import Drheader

scanner = Drheader(url='https://example.com')
scanner.analyze(cross_origin_isolated=True)
```

## How Do I Customise DrHeaderPlus Rules?

DrHeaderPlus relies on a yaml file that defines the policy it will use when auditing security headers. The file is located at `./drheader/resources/rules.yml`, and you can customise it to fit your particular needs. Please follow this [link](RULES.md) if you want to know more.

## Notes

* On ubuntu systems you may need to install libyaml-dev to avoid errors related to a missing yaml.h.

## Who Is Behind It?

DrHeaderPlus is maintained by [@garootman](https://github.com/garootman).

The original drHEADer was developed by the Santander UK Security Engineering team:

* David Albone
* [Javier Dominguez Ruiz](https://github.com/javixeneize)
* Fernando Cabrerizo
* [James Morris](https://github.com/actuallyjamez)
