export RUSTFLAGS := "-D warnings"
export RUSTDOCFLAGS := "-D warnings"

# Список доступных команд
help:
    @just --list

# Форматирование исходного кода
fmt:
    @echo "-> Formatting code"
    @cargo fmt --all

# Выполняет быстрые проверки исходного кода на соответствие стандартам оформления
check:
    @echo "-> Checking code format"
    @cargo fmt --all -- --check

# Выполняет более подробные проверки качества кода
lint:
    @echo "-> Checking code style"
    @cargo clippy --workspace

# Выполняет сборку всех крейтов
build:
    @echo "-> Building all crates"
    @cargo build --workspace

# Запускает все тесты
test:
    @echo "-> Running tests"
    @cargo test --workspace

# Выполняет полную проверку кода перед пушем в репозиторий
prepare: check lint test

