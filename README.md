# PA1445-Group1 

## Introduction

This repo is a replication pakcage for our thesis. In it we aim to investigate the prevalence and usage of VEX files in open source. 

## How to Use
It is recomended to use the dev container for isolation and to have all the helpful tools avilable. 
### Useful commands

Most commands can be run with make, see the [make file](Makefile) or run `make help`:
```
help                           Show this help
install                        Install requirements
```

### Prerequisites

To use you need a GitHub Personal Access Token (PAT) which you can then place in a `.env` file with this name GITHUB_TOKEN="". An example `.env` can be found [here](example.env). As of writing only the classic PAT can access the `seach/code` needed to search for the VEX files. To create a PAT please follow [GitHub's instructions](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-personal-access-token-classic). The `.env` file should then be placed in the github_api folder. While the scripts can be run as on any machine we recommend using docker and the associated devcontainer or compose file. 

### Test

TODO: Explain how unit- or integreation tests can be executed.

### Run

The command `docker-compose up` run from the root directory should run the main scripts. 

## Authors

Made by: 
[Sofia Blom](https://github.com/s02blom) and [Nicholas Joseph Hughes](https://github.com/fimbo4)