# Contributing

PRs are welcome. Here is the path of least resistance.

## Setup

Fork on GitHub, then clone your fork:

```bash
git clone https://github.com/litemars/BeaconDetectionSystem.git
cd BeaconDetectionSystem
```

Set up a virtualenv:

```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

## Workflow

Branch off `main`:

```bash
git checkout -b feature/your-feature-name
```

Use a clear short subject in the commit (`Add: ...`, `Fix: ...`, `Refactor: ...`):

```bash
git commit -m "Add: brief description of changes"
```

Run the tests and the formatter before pushing:

```bash
pytest
black --check control_plane data_plane
```

Push:

```bash
git push origin feature/your-feature-name
```

Open a PR with a description of what changed and why. If you are touching detection logic, mention how you tested it (replay against `eval/`, hand-crafted fixture, etc.) so a reviewer can reproduce the result.
