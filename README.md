# PA1445-Group1 

## Introduction

This repo is a replication pakcage for our thesis. In it we aim to investigate the prevalence and usage of VEX files in open source. 

## How to Use
It is recomended to use the dev container for isolation and to have all the helpful tools avilable. 
### Useful commands

Most commands can be run with make, see the [make file](Makefile) or run `make help`:
```
analysisVEX                    Generates tables and polts of the vex content
createCommitData               Updates the current dabase with information about commits
createVEXData                  Clears the database and get's new data from GitHub
dump                           Creats a mongodump of the database
help                           Show this help
install                        Install requirements
installMongodbTools            Installs Mongodb tools
installPython                  Installs python packeges
lint                           Uses black and isort to lint github_api
restoreDump2026                Restores the database from the dump_2026-03-25
restore                        Restores the database from a mongodump
```

### Prerequisites

Git-Lfs (Large File Storage) is needed for the dump files and can be installed with `sudo apt-get install git-lfs` and then `git lfs install`.

To use you need a GitHub Personal Access Token (PAT) which you can then place in a `.env` file with this name GITHUB_TOKEN="". An example `.env` can be found [here](example.env). As of writing only the classic PAT can access the `seach/code` needed to search for the VEX files. To create a PAT please follow [GitHub's instructions](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-personal-access-token-classic). The `.env` file should then be placed in the github_api folder. While the scripts can be run as on any machine we recommend using docker and the associated devcontainer or compose file. 

### Run

We recommend using the make commands to get started. Please note that both `createVEXData` and `createCommitData` takes several hours to run as they have to query the [GitHub API](https://docs.github.com/en/rest). 

`github_api/main.py` accepts several flags, if no flags are specified then nothing will happen:
```
usage: main.py [-h] [-d] [-hs] [-db]

options:
  -h, --help       show this help message and exit
  -d, --download   Downloads all the vex files to disk
  -hs, --history   Gets the commit hostory for every vex file
  -db, --database  Add the vex files to the database
```

`github_api/analysis.py` has quite a few flags allowing you to customize what you want to focus on:
```
usage: analysis.py [-h] [--all] [-t] [-v] [-db] [--status] [--rating] [-p] [-vuln] [--repo]

options:
  -h, --help            show this help message and exit
  --all                 Performs all the different analyses
  -t, --tools           Analyses the tool usage
  -v, --version         Analyses the different versions of the spesifications
  -db, --databases      Analyses the different databases used
  --status              Analyses the different statuses the vulnerabilites has
  --rating              Analyses the ratings the vulnerabilites has
  -p, --plots           Creats plots or tables for any analyses performed. Stored in the /results folder
  -vuln, --vulnerabilities
                        Analyses the mean mode and median for the number of vulnerabilities
  --repo                Analyses which repositores we have documents from
```

## Authors

Made by: 
[Sofia Blom](https://github.com/s02blom) and [Nicholas Joseph Hughes](https://github.com/fimbo4)
