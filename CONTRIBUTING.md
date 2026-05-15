# Contributing to docker-monitor

Thank you for your interest in contributing!

## Development Environment Setup
1. Clone the repository.
2. Create a virtual environment: `python -m venv venv && source venv/bin/activate`
3. Install dependencies: `pip install -r requirements.txt`
4. Install dev dependencies: `pip install -e .[dev]` or via `pip install pytest black ruff`

## Running Tests
Run the test suite using pytest:
```bash
pytest tests/
```

## PR Guidelines
- One feature or bugfix per PR.
- Clearly describe what was changed and what was tested in the PR description.
- Ensure all tests pass before requesting a review.

## Code Style
- We use `black` for formatting and `ruff` for linting.
- Maximum line length is 100 characters.
