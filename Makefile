.PHONY: dev test lint build deploy logs backup

dev:
	python main.py -web

test:
	pytest tests/ -v

lint:
	black app/ tests/ && flake8 app/

build:
	docker compose build

deploy:
	docker compose up -d

logs:
	docker compose logs -f siati

backup:
	./scripts/deploy.sh backup
