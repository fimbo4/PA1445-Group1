installPython: ## Installs python packeges
	pip install -r github_api/requirements.txt

install: installPython installMongodbTools	## Install requirements

installMongodbTools:	## Installs Mongodb tools
	sudo chmod +x install_MongoDB_Tools.sh
	./install_MongoDB_Tools.sh

run: ## This will create and start the containers for both the database and the main api script
	docker-compose up

lint: ## Uses black and isort to lint github_api
	python -m black github_api/
	isort github_api/

dump: ## Creats a mongodump of the database
	mongodump --host=mongo:27017 --db=Vex --gzip

restore: ## Restores the database from a mongodump
	mongorestore --host=mongo:27017 --gzip

restoreDump2026:
	mongorestore --host=mongo:27017 --gzip ./dump_2026-03-25

# Thanks to Andreas Bauer
help: ## Show this help
	@grep -E '^[.a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'