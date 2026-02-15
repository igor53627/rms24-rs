# Contributing

## Commit Message Format

This project follows the [Conventional Commits](https://www.conventionalcommits.org/) specification.
A `commit-msg` git hook enforces these rules automatically.

### Format

```text
<type>(<optional-scope>)[!]: <subject>
```

- **type** (required): one of `feat`, `fix`, `docs`, `test`, `chore`, `refactor`, `ci`, `build`, `perf`, `style`, `bench`
- **scope** (optional): a lowercase identifier in parentheses, e.g. `(parser)`
- **`!`** (optional): append `!` before the colon to indicate a breaking change
- **subject** (required): starts with a lowercase letter; the entire first line must be 72 characters or fewer

### Allowed Types

| Type       | Description                              |
|------------|------------------------------------------|
| `feat`     | A new feature                            |
| `fix`      | A bug fix                                |
| `docs`     | Documentation only changes               |
| `test`     | Adding or updating tests                 |
| `chore`    | Maintenance tasks                        |
| `refactor` | Code change that neither fixes nor adds  |
| `ci`       | CI/CD configuration changes              |
| `build`    | Build system or dependency changes       |
| `perf`     | Performance improvements                 |
| `style`    | Code style changes (formatting, etc.)    |
| `bench`    | Benchmark additions or changes           |

### Examples

Good:
```text
feat: add user authentication
fix(parser): handle empty input
docs: clarify keywordpir collision routing
test: add coverage for edge cases
chore: update dependencies
feat!: drop support for legacy format
refactor(api)!: rename endpoint parameters
```

Bad:
```text
Add user authentication          # missing type
feat: Add user authentication    # subject starts with uppercase
FEAT: add user auth              # type must be lowercase
feat add user authentication     # missing colon after type
```

### Exceptions

Merge commits (`Merge ...`) and fixup/squash commits (`fixup! ...`, `squash! ...`) are allowed through without validation.

## Installing the Hook

Run the install script to set up the commit-msg hook locally:

```sh
./scripts/install-hooks.sh
```
