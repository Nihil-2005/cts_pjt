.PHONY: help install test deploy scan pipeline dashboard clean all

help:
	@echo "DevSecOps Risk Intelligence Pipeline"
	@echo ""
	@echo "Targets:"
	@echo "  make all              Full pipeline: deploy + scan + process + dashboard"
	@echo "  make deploy-targets  Start NodeGoat, Juice Shop, bWAPP"
	@echo "  make run-scanners     Run all 4 scanners against targets"
	@echo "  make run-pipeline     Process findings through 8 stages"
	@echo "  make dashboard        Generate HTML dashboard"
	@echo "  make test             Run unit tests"
	@echo "  make clean            Remove outputs and caches"
	@echo ""

install:
	pip install -r requirements.txt

deploy-targets:
	docker compose -f targets/docker-compose.yml up -d
	@echo "⏳ Waiting 30s for targets to start..."
	sleep 30

run-scanners: deploy-targets
	mkdir -p scan_reports
	# Nuclei
	docker run --rm --network=host -v $(PWD)/scan_reports:/out \
		projectdiscovery/nuclei:latest \
		-u http://localhost:4000 -j -o /out/nodegoat_nuclei.json || true
	docker run --rm --network=host -v $(PWD)/scan_reports:/out \
		projectdiscovery/nuclei:latest \
		-u http://localhost:3000 -j -o /out/juiceshop_nuclei.json || true
	docker run --rm --network=host -v $(PWD)/scan_reports:/out \
		projectdiscovery/nuclei:latest \
		-u http://localhost:80 -j -o /out/bwapp_nuclei.json || true
	# ZAP
	docker run --rm --network=host -v $(PWD)/scan_reports:/zap/wrk \
		ghcr.io/zaproxy/zaproxy:stable \
		zap-baseline.py -t http://localhost:4000 -J /zap/wrk/nodegoat_zap.json || true
	docker run --rm --network=host -v $(PWD)/scan_reports:/zap/wrk \
		ghcr.io/zaproxy/zaproxy:stable \
		zap-baseline.py -t http://localhost:3000 -J /zap/wrk/juiceshop_zap.json || true
	docker run --rm --network=host -v $(PWD)/scan_reports:/zap/wrk \
		ghcr.io/zaproxy/zaproxy:stable \
		zap-baseline.py -t http://localhost:80 -J /zap/wrk/bwapp_zap.json || true
	# Trivy
	docker run --rm -v $(PWD)/scan_reports:/out aquasec/trivy:latest \
		image --format json -o /out/nodegoat_trivy.json webgoat/webgoat:latest || true
	docker run --rm -v $(PWD)/scan_reports:/out aquasec/trivy:latest \
		image --format json -o /out/juiceshop_trivy.json bkimminich/juice-shop:latest || true

run-pipeline:
	mkdir -p outputs
	python -m pipeline.run \
		--reports scan_reports/ \
		--config config.json \
		--out outputs/

dashboard:
	python -m pipeline.dashboard \
		--findings outputs/ranked_findings.json \
		--out outputs/risk_dashboard.html
	@echo "Dashboard generated: outputs/risk_dashboard.html"

all: deploy-targets run-scanners run-pipeline dashboard
	@echo "✅ Full pipeline complete!"

test:
	python -m pytest pipeline/tests/ -v --tb=short

test-coverage:
	python -m pytest pipeline/tests/ --cov=pipeline --cov-report=html

clean:
	rm -rf outputs/ scan_reports/ intel/ .threat_cache/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	docker compose -f targets/docker-compose.yml down 2>/dev/null || true
