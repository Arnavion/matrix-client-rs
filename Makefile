.PHONY: clean default outdated print test

default:
	cargo build --release

clean:
	rm -rf Cargo.lock target/

outdated:
	cargo-outdated

print:
	git status --porcelain

test:
	cargo test --workspace
	cargo clippy --workspace --tests --examples
