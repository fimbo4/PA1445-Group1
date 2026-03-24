#!/bin/bash
URL="https://fastdl.mongodb.org/tools/db/mongodb-database-tools-debian12-x86_64-100.15.0.deb"
DEST="/home/vscode/mongodb-database-tools-debian12-x86_64-100.15.0.deb"

curl -L -o "$DEST" "$URL"
sudo apt install "$DEST"