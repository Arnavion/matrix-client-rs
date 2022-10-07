.PHONY: clean default test

default:
	cargo build --release

clean:
	rm -rf Cargo.lock target/

test:
	cargo test --all
	cargo clippy --all --tests --examples
