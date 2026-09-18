# ---------------------------------------------------------------------------
# DocuTrust developer commands.
#
# These wrap the underlying tools rather than replacing them; every target
# prints what it runs, so nothing here is a black box.
#
# Windows: the bodies are plain shell. Run them under Git Bash or WSL, or use
# the PowerShell equivalents documented in README.md.
# ---------------------------------------------------------------------------

.DEFAULT_GOAL := help
.PHONY: help dev up down logs build test backend-test frontend-test security-test \
	    generate-dev-cert samples clean docker-build verify-flow

help: ## Show available commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ------------------------------- run ---------------------------------------

up: ## Start the full stack (Postgres, MinIO, backend, frontend)
	docker compose up -d --build

down: ## Stop the stack and remove volumes
	docker compose down -v

logs: ## Follow backend logs
	docker compose logs -f backend

dev: ## Run backend and frontend locally without Docker (two terminals needed)
	@echo "Terminal 1:  cd backend  && mvn spring-boot:run"
	@echo "Terminal 2:  cd frontend && npm run dev"
	@echo ""
	@echo "The local profile uses in-memory H2 and filesystem storage,"
	@echo "so no external services are required."

# ------------------------------ build --------------------------------------

build: ## Build backend jar and frontend bundle
	cd backend  && mvn -B clean package -DskipTests
	cd frontend && npm run build

docker-build: ## Build both container images
	docker compose build

# ------------------------------ tests --------------------------------------

test: backend-test frontend-test ## Run every test suite

backend-test: ## Run backend unit and cryptographic tests
	cd backend && mvn -B test

frontend-test: ## Run frontend tests
	cd frontend && npm test

security-test: ## Run the digital signature attack simulation suite
	cd backend && mvn -B -Dtest=DigitalSignatureAttackSuiteTest test

verify-flow: ## Drive the full upload/sign/verify/tamper demo against a running backend
	pwsh -File scripts/demo-flow.ps1 || powershell -File scripts/demo-flow.ps1

# ------------------------------- PKI ---------------------------------------

generate-dev-cert: ## Generate a development PKI into ./pki-local (gitignored)
	cd backend && mvn -B -q test-compile
	cd backend && mvn -B -q dependency:build-classpath -Dmdep.outputFile=target/cp.txt
	cd backend && java -cp "target/classes:target/test-classes:$$(cat target/cp.txt)" \
	  com.docutrust.certificate.devpki.DevPkiWriter ../pki-local

samples: ## Regenerate the sample PDFs in ./samples
	cd backend && mvn -B -q test-compile
	cd backend && mvn -B -q dependency:build-classpath -Dmdep.outputFile=target/cp.txt
	cd backend && java -cp "target/classes:target/test-classes:$$(cat target/cp.txt)" \
	  com.docutrust.testsupport.SampleDocumentWriter ../samples

# ------------------------------ cleanup ------------------------------------

clean: ## Remove build output and local data
	cd backend  && mvn -B clean
	rm -rf frontend/dist frontend/node_modules/.vite
	rm -rf backend/.data
