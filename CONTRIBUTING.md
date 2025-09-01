# Contributing

Thank you for considering contributing to our project. Your help if very welcome!

Feel free to discuss the change you wish to make via issue, email, or any other method with
the owners of this repository before making a change.

## Getting started

In order to make your contribution please make a fork of the repository. After you've pulled the code, follow these
recommendations to kick start the development:

- compile with *stable* rust
- use `cargo fmt`
- check the output of `cargo clippy --all-features --all --tests`
- run tests `cargo test`

## Pull Request Process

1. We follow [Conventional Commits](https://www.conventionalcommits.org/en/) in our commit messages, i.e.
   `feat(core): improve typing`
2. Update [README.md](README.md) to reflect changes related to public API and everything relevant
3. Make sure you cover all code changes with tests
4. When you are ready, create Pull Request of your fork into original repository
