# 🤝 Contributing to VisuaLogin Core

We love your input! We want to make contributing to VisuaLogin Core as easy and transparent as possible.

## Quick Links
- [Report a Bug](#-reporting-bugs)
- [Suggest an Enhancement](#-suggesting-enhancements)
- [Your First Contribution](#-first-time-contributors)
- [Pull Request Process](#-pull-request-process)
- [Code Standards](#-code-standards)

## 🐛 Reporting Bugs

**Before submitting a bug report:**
1. Check if the bug hasn't been [already reported](https://github.com/VisuaLogin/core/issues)
2. Test using the latest version of the code

**How to report:**
```markdown
**Description**
Clear and concise description of the bug.

**Steps to Reproduce**
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

**Expected Behavior**
What you expected to happen.

**Screenshots**
If applicable, add screenshots to help explain.

**Environment:**
- OS: [e.g. Windows 10, macOS 12.0]
- Node.js Version: [e.g. 18.0.0]
- Browser: [e.g. Chrome 96, Firefox 94]

**Additional Context**
Add any other context about the problem here.
```

## 💡 Suggesting Enhancements

We welcome feature ideas! Please:

1. Use the feature request template
2. Explain the problem you're trying to solve
3. Describe your proposed solution
4. Include examples or mockups if possible
5. Consider whether it aligns with our mission of accessibility and security

## 👶 First Time Contributors

Welcome! Here's how to get started:

1. **Find an issue** labeled `good first issue` or `help wanted`
2. **Comment on the issue** that you'd like to work on it
3. **Fork the repository** and create your feature branch:
   ```bash
   git checkout -b feature/amazing-feature
   ```
4. **Make your changes** following our code standards
5. **Test your changes** thoroughly
6. **Submit a pull request**

Need help? Don't hesitate to ask in the issue comments!

## 🔧 Development Setup

1. **Fork and clone** the repository
2. **Install dependencies**:
   ```bash
   npm install
   ```
3. **Run basic tests**:
   ```bash
   npm test
   ```
4. **Try the recovery CLI**:
   ```bash
   npm run recovery
   ```

## 📋 Pull Request Process

1. **Update documentation** for any user-facing changes
2. **Add tests** for new functionality
3. **Ensure all tests pass** - `npm test`
4. **Follow our commit message conventions**:
   - `feat:` for new features
   - `fix:` for bug fixes
   - `docs:` for documentation changes
   - `test:` for test additions/modifications
   - `chore:` for maintenance tasks

Example: `feat: add pattern validation for empty arrays`

5. **Request review** from maintainers
6. **Address review feedback** promptly

## 🎨 Code Standards

### JavaScript/Node.js
- Use ES6+ features where appropriate
- Follow consistent naming conventions
- Include JSDoc comments for public methods
- Prefer async/await over callbacks

### Security Considerations
- Never hardcode sensitive values
- Use the built-in `secureWipe` function for sensitive data
- Validate all user inputs rigorously
- Follow cryptographic best practices

### Documentation
- Update README.md for user-facing changes
- Document new API methods with examples
- Keep code comments clear and concise

## 🧪 Testing

- Write tests for new functionality
- Ensure tests cover edge cases
- Cryptographic functions require extensive testing
- Browser compatibility must be maintained

```javascript
// Example test structure
describe('password generation', () => {
  it('should generate valid passwords', async () => {
    const result = await generatePassword(testData);
    expect(result).toMeetComplexityRequirements();
  });
});
```

## ❓ Questions?

- **Documentation issues**: Open an issue with the `documentation` label
- **Security concerns**: Email visualogin@proton.me(do not open public issues)
- **General questions**: Use GitHub Discussions or issue comments

## 📜 License

By contributing, you agree that your contributions will be licensed under the same AGPLv3 license that covers the project.

## 🙏 Thank You!

Your contributions help make digital security accessible to everyone. Thank you for helping us build a more secure and inclusive internet!
