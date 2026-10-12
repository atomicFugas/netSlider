# Golden reuse fixtures (R6)

Stable expected summaries for headless `madrigal apply` / `validate` against
the checked-in demo corpus. Counts are intentional; full provenance dumps are
omitted so fixtures stay portable across machines.

| File | Meaning |
|------|---------|
| `expected_apply_extra.json` | Apply `device_v1.yaml` to `extra.pcap` (both directions) |
| `expected_validate_main.json` | Validate `device_v1.yaml` on `main.pcap` counters |

Regenerate after intentional interpretation/corpus changes:

```bash
python -m madrigal.demo.corpus.golden
```
