# Contributing to eBPF Beacon Detection System

Thank you for your interest in contributing! This document provides guidelines and instructions for contributing to this project.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/yourusername/BeaconDetectionSystemGit.git
   cd BeaconDetectionSystemGit
   ```

3. **Set up the development environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

## Development Workflow

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** and commit them with clear messages:
   ```bash
   git commit -m "Add: brief description of changes"
   ```

3. **Run tests and linting**:
   ```bash
   pytest
   pylint control_plane data_plane
   black --check control_plane data_plane
   ```

4. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

5. **Create a Pull Request** with a clear description of your changes

## Testing

- Write tests for new features in the `tests/` directory
- Ensure all tests pass: `pytest`
- Aim for high test coverage, especially for critical components
- Use descriptive test names that explain what is being tested

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Provide clear steps to reproduce bugs
- Include relevant system information and logs

## Documentation

- Update relevant documentation for new features
- Keep the README.md up to date

## Questions?

Feel free to open an issue or discussion for questions.
