# Contributing to Database Detector

Thank you for considering contributing to Database Detector!

## How to Contribute

### Reporting Bugs
- Use GitHub Issues
- Describe the bug clearly
- Include steps to reproduce
- Provide system information (OS, Python version)

### Suggesting Features
- Open a GitHub Issue with [Feature Request] tag
- Describe the use case
- Explain expected behavior

### Pull Requests
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-database-support`)
3. Make your changes
4. Add tests if applicable
5. Update documentation
6. Submit pull request

### Code Style
- Follow PEP 8
- Use type hints
- Add docstrings for functions
- Keep code simple and readable

### Adding Database Support
To add a new database:
1. Add port to `DB_PORTS` dictionary
2. Implement banner grabbing in `_grab_banner()`
3. Add signature to `_verify_protocol()`
4. Test thoroughly
5. Update README

## Questions?
Open an issue
