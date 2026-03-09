install: ## Install requirements
	pip install -r github_api/requirements.txt

run: ## This will create and start the containers for both the database and the main api script
	docker-compose up

# Thanks to Andreas Bauer
help: ## Show this help
	@grep -E '^[.a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'