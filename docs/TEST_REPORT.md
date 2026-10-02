# MAFKit v3.1 Automated Test Report

## Result

`132 passed`

## Coverage

Overall Python line coverage: **92%**.

| Module | Coverage |
|---|---:|
| `mafkit/__init__.py` | 100% |
| `mafkit/attack.py` | 100% |
| `mafkit/forensic.py` | 100% |
| `mafkit/model.py` | 100% |
| `mafkit/util.py` | 100% |
| `mafkit/correlation.py` | 96% |
| `mafkit/behavior.py` | 92% |
| `mafkit/adbcollect.py` | 89% |
| `mafkit/cli.py` | 89% |
| `mafkit/deobfuscation.py` | 88% |
| `mafkit/plugins/dpt.py` | 88% |
| `mafkit/reporting.py` | 88% |
| `mafkit/dex.py` | 85% |
| `mafkit/device.py` | 85% |
| `mafkit/analyzers.py` | 84% |
| `mafkit/plugins/base.py` | 83% |

## Commands

```bash
pytest -q
coverage erase
coverage run -m pytest -q
coverage report -m
python -m compileall -q mafkit tests
```

## Interpretation

The suite is designed around forensic failure modes, not only happy-path feature testing. Passing tests and line coverage do not constitute legal admissibility certification or scientific validation. Examiners remain responsible for validating important automated findings and complying with local evidence rules.
