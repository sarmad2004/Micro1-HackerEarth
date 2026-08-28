# agentgate - build and verification entry points.
#
# `make` builds both implementations and runs every check. No network access is
# required at any point: neither implementation has external dependencies.

CPP_BUILD    := cpp/build
RUST_TARGET  := rust/target/release
PY           := python3

CPP_BASE     := $(CPP_BUILD)/agentgate-baseline
CPP_ADV      := $(CPP_BUILD)/agentgate-advanced
RS_BASE      := $(RUST_TARGET)/agentgate-baseline
RS_ADV       := $(RUST_TARGET)/agentgate-advanced

GATES        := --gate cpp-base=$(CPP_BASE) --gate cpp-adv=$(CPP_ADV) \
                --gate rs-base=$(RS_BASE)  --gate rs-adv=$(RS_ADV)

.PHONY: all build build-cpp build-rust test verify eval eval-heldout \
        differential robustness bench corpus clean dist help

all: verify

## build --------------------------------------------------------------------

build: build-cpp build-rust

build-cpp:
	@cmake -S cpp -B $(CPP_BUILD) -DCMAKE_BUILD_TYPE=Release >/dev/null
	@cmake --build $(CPP_BUILD) -j

build-rust:
	@cd rust && cargo build --release

## unit tests ---------------------------------------------------------------

test: build
	@echo "== C++ unit tests =="
	@$(CPP_BUILD)/agentgate_tests
	@echo "== Rust unit tests =="
	@cd rust && cargo test --quiet

## measurements -------------------------------------------------------------

corpus:
	@$(PY) corpus/build_corpus.py
	@$(PY) corpus/build_heldout.py

eval: build
	@echo "== Development corpus =="
	@$(PY) eval/evaluate.py $(GATES)

eval-heldout: build
	@echo "== Held-out set =="
	@$(PY) eval/evaluate.py --corpus corpus/heldout $(GATES)

differential: build
	@echo "== Cross-language conformance =="
	@$(PY) eval/differential.py \
	  --pair baseline=$(CPP_BASE),$(RS_BASE) \
	  --pair advanced=$(CPP_ADV),$(RS_ADV)

robustness: build
	@echo "== Adversarial resource stress =="
	@$(PY) eval/robustness.py $(GATES) \
	  --fail-closed-gate cpp-adv --fail-closed-gate rs-adv

bench: build
	@echo "== Throughput =="
	@$(PY) eval/bench.py $(GATES) --repeat 300 --rounds 3

## the full gate ------------------------------------------------------------

verify: test eval eval-heldout differential robustness
	@echo
	@echo "All checks passed."

## packaging ----------------------------------------------------------------

dist: verify
	@bash scripts/make_dist.sh

clean:
	@rm -rf $(CPP_BUILD) rust/target dist
	@echo "cleaned"

help:
	@echo "make build         build both implementations"
	@echo "make test          unit tests (C++ and Rust)"
	@echo "make eval          score all four gates on the development corpus"
	@echo "make eval-heldout  score all four gates on the held-out set"
	@echo "make differential  assert C++ and Rust agree byte-for-byte"
	@echo "make robustness    attack the resource bounds with hostile input"
	@echo "make bench         throughput benchmark"
	@echo "make verify        everything above (default)"
	@echo "make dist          verify, then build the submission zip"
	@echo "make clean         remove build outputs"
