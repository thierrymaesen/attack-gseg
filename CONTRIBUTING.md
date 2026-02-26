# Contributing to ATT&CK Ground Segment Threat Graph

Thank you for your interest in contributing to this project!

## How to Contribute

1. **Fork** the repository
2. **Create a branch** from `main` for your feature or fix
3. **Write tests** for any new functionality
4. **Run the test suite** to make sure everything passes:
   ```bash
   poetry run pytest tests/ -v
   ```
5. **Check formatting** with Black and Ruff:
   ```bash
   poetry run black src/ tests/
   poetry run ruff check src/ tests/
   ```
6. **Open a Pull Request** with a clear description of your changes

## Development Setup

```bash
# Clone the repository
git clone https://github.com/thierrymaesen/attack-gseg.git
cd attack-gseg

# Install dependencies with Poetry
poetry install

# Run the full test suite
poetry run pytest tests/ -v --cov=src --cov-report=term-missing
```

## Code Style

- **Formatter**: Black (line-length=100)
- **Linter**: Ruff
- **Type hints**: encouraged on all public functions
- **Docstrings**: Google style

## Reporting Issues

Please open an issue on GitHub with:
- A clear title and description
- Steps to reproduce the problem
- Expected vs actual behavior
- Python version and OS

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
