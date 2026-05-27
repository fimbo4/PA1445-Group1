installPython: ## Installs python packeges
	pip install -r github_api/requirements.txt

install: installPython installMongodbTools	## Install requirements

installMongodbTools:	## Installs Mongodb tools
	sudo chmod +x install_MongoDB_Tools.sh
	./install_MongoDB_Tools.sh

createVEXData: ## Clears the database and get's new data from GitHub
	python3 github_api/main.py --clear-database --database --history

createCommitData: ## Updates the current dabase with information about commits
	python3 github_api/gen_commit_diff.py

analysisFull: analysisVEX analysisCommits ## Runs all the analysis

analysisVEX: ## Generates tables and polts of the vex content
	python3 github_api/analysis.py --all --plots

analysisCommits: ## Analyses the commits
	python3 github_api/commit_diff_analysis.py

lint: ## Uses black and isort to lint github_api
	python -m black github_api/
	isort github_api/

dump: ## Creats a mongodump of the database
	mongodump --host=mongo:27017 --db=Vex --gzip

restore: ## Restores the database from a mongodump
	mongorestore --host=mongo:27017 --gzip

restoreDump2026:	## Restores the database from the dump_2026-03-25
	mongorestore --host=mongo:27017 --gzip ./dump_2026-03-25

# Thanks to Andreas Bauer
help: ## Show this help
	@grep -E '^[.a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'