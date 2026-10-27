# CS07 Sanjivani NGFW - common tasks. Run from the repository root.
PY ?= python3
P3 := part3_rulebase_policy/tools

.PHONY: all check test lint verify sim docs risk clean

all: check test

## check: every offline gate a policy change must pass
check: lint verify
	cd part2_architecture_protocols/tools && $(PY) validate_objects.py
	cd $(P3) && $(PY) check_lab_subset.py
	cd part4_lab_monitoring_response/compliance && $(PY) metrics.py

lint:
	cd $(P3) && $(PY) lint_policy.py

verify:
	cd $(P3) && $(PY) verify_matrix.py -q

test:
	$(PY) -m pytest -q

## sim: Part I simulator demos
sim:
	cd part1_foundations_threats_risk && PYTHONPATH=../common $(PY) -m fwsim scenarios
	cd part1_foundations_threats_risk && PYTHONPATH=../common $(PY) -m fwsim incidents

## docs: regenerate every generated file from objects.yaml and policy.yaml
docs:
	cd part2_architecture_protocols/tools && $(PY) render_docs.py
	cd $(P3) && $(PY) gen_acl.py --format csv -o ../rulebase/rulebase.csv
	cd $(P3) && $(PY) gen_acl.py --format pf  -o ../generated/sanjivani.pf
	cd $(P3) && $(PY) gen_acl.py --format md  -o ../generated/rulebase.md

risk:
	cd part1_foundations_threats_risk/risk && $(PY) heatmap.py --out-dir figures

clean:
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	rm -rf .pytest_cache
