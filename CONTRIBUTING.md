# Contributing

Issues and pull requests are welcome.

- **Bugs:** include your AdGuard Home version, how you run AdGuard Stats (podman or local), and the
  output of `scripts/pod.sh logs` if the collector is involved.
- **Categories:** new or better domain rules go in [`app/data/categories.json`](app/data/categories.json)
  (category → service → domain suffixes). This is the easiest way to contribute.
- **Code:** run the tests before opening a pull request:

  ```bash
  pip install -r requirements.txt pytest httpx
  python -m pytest tests
  ```

  `scripts/dev.sh` starts the dashboard against a fake AdGuard Home with synthetic data.
