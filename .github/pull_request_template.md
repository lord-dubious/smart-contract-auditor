## Summary

- 

## Verification

- [ ] `ruff check src tests`
- [ ] `ruff format --check src tests`
- [ ] `python -m compileall -q src tests`
- [ ] `pytest tests/`

## Security Boundaries

- [ ] External tool/model failures are logged or surfaced in result metadata.
- [ ] Mock/demo mode behavior is clearly labeled and not presented as real verification.
- [ ] Generated Gemini/Foundry output was manually reviewed before being treated as evidence.
