DC=docker-compose

up:
	$(DC) up -d --renew-anon-volumes

down:
	$(DC) down -v

build:
	$(DC) build

rebuild:
	$(DC) up -d --build --renew-anon-volumes

migrate:
	$(DC) exec backend python manage.py migrate

createsuperuser:
	$(DC) exec backend python manage.py createsuperuser

logs:
	$(DC) logs -f backend celery

shell:
	$(DC) exec backend python manage.py shell

frontend-logs:
	$(DC) logs -f frontend

all-logs:
	$(DC) logs -f

restart:
	$(DC) down && $(DC) up -d
