# tengine-fuzz-lab

Black-box fuzzing harness for self-hosted Tengine 3.1.0 security research.

- `lab/setup_ci.sh` - build normal + ASAN instances, rewrite-heavy config
- `lab/fuzz/blackfuzz.py` - grammar-guided black-box HTTP fuzzer with crash detection
- `lab/triage_ci.sh` - replay crashers against ASAN build, collect reports

For local authorized security research only.
