# Contributing

Contributions are welcome and greatly appreciated! Every little bit helps and credit will always be given. You can
contribute in many ways:

### Report a bug

Report a bug on the [issue tracker](https://github.com/garootman/DrHeaderPlus/issues).

Please include in the report:

- Your operating system name and version
- Any details about your local setup that might be helpful in troubleshooting
- Detailed steps to reproduce the bug

### Fix a bug

Look through the [bug tracker](https://github.com/garootman/DrHeaderPlus/labels/bug) for open issues.
Anything tagged with `bug` and `help wanted` is open to whoever wants to fix it.

### Implement a new feature

Look through the [issue tracker](https://github.com/garootman/DrHeaderPlus/labels/enhancement) for open
feature requests. Anything tagged with `enhancement` and `help wanted` is open to whoever wants to implement it.

### Write documentation

DrHeaderPlus documentation can always be enhanced, whether as part of the official docs, in docstrings, or even on
the web such as in blog posts and articles.

### Submit feedback

The best way to send feedback is to open an issue on the
[issue tracker](https://github.com/garootman/DrHeaderPlus/issues).

If you are proposing a feature:

- Explain in detail how it would work
- Keep the scope as narrow as possible to make it easier to implement
- Remember that this is a volunteer-driven project, and that contributions are welcome

## Get Started!

Ready to contribute? This section walks through how to set up DrHeaderPlus for local development and prepare a pull request.

#### Pre-requisites

DrHeaderPlus is built using Python 3.12+ and [uv](https://docs.astral.sh/uv/).

1. Install [Python 3.12+](https://www.python.org/downloads)

2. Install [uv](https://docs.astral.sh/uv/getting-started/installation/)

3. Fork DrHeaderPlus into your GitHub account

4. Clone your fork locally
   ```shell
   $ git clone git@github.com:<your-github-username>/DrHeaderPlus.git
   ```

5. Install project dependencies
   ```shell
   $ uv sync --extra dev
   ```

6. Create a branch for local development
   ```shell
   $ git checkout -b <name-of-your-bug-fix-or-feature>
   ```

7. After making your changes, verify that the tests and required checks are passing
   ```shell
   $ make check
   ```

8. Commit your changes and push your branch
   ```shell
   $ git add .
   $ git commit -m '<description of your changes>'
   $ git push origin <name-of-your-bug-fix-or-feature>
   ```

9. Submit a pull request at <https://github.com/garootman/DrHeaderPlus/pulls>

## Pull Request Guidelines

When submitting a pull request, please ensure that:

1. The existing tests are passing, and new functionality is adequately covered with new tests
2. The relevant documentation e.g. `README.md`, `RULES.md`, `CLI.md` is updated to reflect new or changed functionality
3. The code works for Python >= 3.12
4. The pull request is submitted against the `main` branch with no merge conflicts
5. The pull request pipeline has succeeded
