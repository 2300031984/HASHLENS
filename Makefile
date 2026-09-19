.PHONY: help install test run-backend run-dashboard demo docker-up docker-down clean

help:
	@echo "HashLens Management Commands:"
	@echo "  make install         - Install backend & dashboard dependencies"
	@echo "  make test            - Run all pytest test suites (unit, API, security)"
	@echo "  make run-backend     - Launch FastAPI REST API server (port 8000)"
	@echo "  make run-dashboard   - Launch Streamlit SOC Dashboard (port 8501)"
	@echo "  make demo            - Run reproducible 13-step acceptance demo"
	@echo "  make docker-up       - Build and launch multi-container stack via Docker Compose"
	@echo "  make docker-down     - Stop container stack"
	@echo "  make clean           - Remove temporary data and caches"

install:
	python -m pip install -r backend/requirements.txt -r dashboard/requirements.txt

test:
	python -m pytest tests/ -v

run-backend:
	python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload

run-dashboard:
	python -m streamlit run dashboard/app.py --server.port 8501 --server.address 0.0.0.0

demo:
	python scripts/demo.py

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down

clean:
	rm -rf .pytest_cache data/test_hashlens.db temp/*
