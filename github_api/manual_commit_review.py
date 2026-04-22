from database import vexDB
import random
import os
import json 
from tqdm import tqdm
from main import retry_request

db = vexDB()
random.seed("vex")

SAMPLE_SIZE = 100

commit_urls = []

def random_document_indexes(collection_size, num_docs) -> list:
    if num_docs <= collection_size:
        return random.sample(range(collection_size), num_docs)
    else:
        return random.sample(range(collection_size), collection_size)


def gen_doc_lists():
    collections = db.get_collections()
    for collection in collections:
        doc_indexes = random_document_indexes(db.get_collection_size(collection), SAMPLE_SIZE)
        documents = db.retrieve_collection_data(collection)
        index = 0
        for document in documents:
            if index in doc_indexes:
                commits = retry_request(document["commit_url"])
                commit_list = []
                if commits is not None:
                    commits = commits.json()
                    for commit in commits:
                        commit_list.append(commit["html_url"])
                commit_urls.append((collection, commit_list))    
            index += 1


def loop(index: int, commit_data: dict):
    index_reached = False
    cur_index = 0
    for collection, commits in tqdm(
        commit_urls,
        desc="Analyzing documents",
        total=len(commit_urls),
        unit="documents",
    ):
        cloop = True
        for commit in commits:
            if (cur_index == index or index_reached) and cloop:
                index_reached = True
                print(commit)
                user_entry = input("add, ini, upd, del, unk, nf: ")
                if "nf" in user_entry:
                    cloop = False
                if "add" in user_entry:
                    commit_data[collection]["added"] += 1
                if "ini" in user_entry:
                    commit_data[collection]["init"] += 1
                if "upd" in user_entry:
                    commit_data[collection]["updated"] += 1
                if "del" in user_entry:
                    commit_data[collection]["deleted"] += 1
                if "unk" in user_entry:
                    commit_data[collection]["unknown"] += 1
                cur_index += 1
                commit_data["index"] = cur_index
                with open("commit_data.json", "w") as cd:
                    json.dump(commit_data, cd)
            else:
                cur_index += 1
                continue
            
        commit_data["index"] = cur_index
        with open("commit_data.json", "w") as cd:
            json.dump(commit_data, cd)


def main():
    commit_data = {}
    if os.path.exists("commit_data.json"):
        with open("commit_data.json", "r") as cd:
            commit_data = json.loads(cd.read())
    else:
        fresh_data = {
                "index": 0,
                "OpenVEX": {
                    "added": 0,
                    "init": 0,
                    "updated": 0,
                    "deleted": 0,
                    "unknown": 0
                },
                "CSAF": {
                    "added": 0,
                    "init": 0,
                    "updated": 0,
                    "deleted": 0,
                    "unknown": 0
                },
                "CycloneDX": {
                    "added": 0,
                    "init": 0,
                    "updated": 0,
                    "deleted": 0,
                    "unknown": 0
                },
                "SPDX": {
                    "added": 0,
                    "init": 0,
                    "updated": 0,
                    "deleted": 0,
                    "unknown": 0
                }
            }
        with open("commit_data.json", "w") as cd:
            json.dump(fresh_data, cd)
        commit_data = fresh_data
    gen_doc_lists()
    loop(commit_data["index"], commit_data)


if __name__ == "__main__":
    main()