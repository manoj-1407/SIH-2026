# RC2 validation report status

The previous static report was removed because it contained stale test counts,
an unsupported "certified" label, and recovery precision/recall values that
were not produced by the current strict scorer. Do not cite those figures.

To regenerate this execution-only report after running the current gate:

```powershell
python scripts\bootstrap_and_verify.py
```

Current measured recovery and performance results are published in
[FINAL_BENCHMARK_REPORT.md](FINAL_BENCHMARK_REPORT.md). Its synthetic and
logical-only boundaries apply; it does not claim real-media validation.
