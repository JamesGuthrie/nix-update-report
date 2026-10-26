# Run in the dev shell (nix develop).

.PHONY: check check-nix

check:
	cd scripts && python3 -m unittest
	ty check scripts tests
	actionlint

# Evaluates the NixOS configuration in tests/fixture, about a minute.
check-nix:
	python3 -m unittest discover -s tests
