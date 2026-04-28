import random
import re

from database import vexDB
from main import retry_request
from tqdm import tqdm

random.seed("vex")

CDX_VEX_HEUR = ["vulnerabilities", "affects", "ratings", "cwes"]
CSAF_VEX_HEUR = ["vulnerabilities", "csaf_vex", "affected"]
SPDX_VEX_HEUR = ["Vulnerability"]

<<<<<<< HEAD
=======
SAMPLE_SIZE = 600


def random_document_indexes(collection_size, num_docs) -> list:
    if num_docs <= collection_size:
        return random.sample(range(collection_size), num_docs)
    else:
        return random.sample(range(collection_size), collection_size)


def gen_doc_indexes(database: vexDB) -> dict:
    ids = {"OpenVEX": [], "CSAF": [], "SPDX": [], "CycloneDX": []}
    collections = database.get_collections()
    for collection in collections:
        doc_indexes = random_document_indexes(
            database.get_collection_size(collection), SAMPLE_SIZE
        )
        documents = database.retrieve_collection_data(collection)
        index = 0
        for document in documents:
            if index in doc_indexes:
                ids[collection].append(document["_id"])
            index += 1
    return ids

>>>>>>> 994d915cd7bc9442b876e49bb35fe1e163d572ef

def parse_diff(patch, filetype):
    added_lines = []
    remov_lines = []

    for line in patch.splitlines():
        if line[0] == "-":
            line = line[1:]
            remov_lines.append(line)
        elif line[0] == "+":
            line = line[1:]
            added_lines.append(line)

    added_keys = []
    remov_keys = []

    if filetype == "json" or filetype == "jsonld":
        for line in added_lines:
            keys = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"\s*:', line)
            added_keys += keys
        for line in remov_lines:
            keys = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"\s*:', line)
            remov_keys += keys
    elif filetype == "xml":
        for line in added_lines:
            tags = re.findall(r"</?[^>]+>", line)
            added_keys += tags
        for line in remov_lines:
            tags = re.findall(r"</?[^>]+>", line)
            remov_keys += tags

    updated_keys = list(set(added_keys) & set(remov_keys))
    added_keys = list(set(added_keys) - set(updated_keys))
    remov_keys = list(set(remov_keys) - set(updated_keys))

    return {
        "added_fields": added_keys,
        "removed_fields": remov_keys,
        "updated_fields": updated_keys,
    }


def categorize_change(patch, filetype, specification):

    probably_vex = False
    kwords = []

    if specification == "CycloneDX":
        kwords = CDX_VEX_HEUR
    elif specification == "CSAF":
        kwords = CSAF_VEX_HEUR
    elif specification == "SPDX":
        kwords = SPDX_VEX_HEUR
    elif specification == "OpenVEX":
        probably_vex = True

    for keyword in kwords:
        if keyword in patch:
            probably_vex = True
            break

    if probably_vex:
        return parse_diff(patch, filetype)
    else:
        return None


def get_commit_diffs(commit_data, filename, filetype, specification):
    commit_list = []
    for commit in commit_data:
        commit_instance = {
            "patches": []
        }
        if commit is None:
            continue
        commit_diffs = retry_request(commit["url"])
        if commit_diffs is None:
            continue
        commit_diffs = commit_diffs.json()
        commit_timestamp = None
<<<<<<< HEAD
        if ("commit" in commit_diffs.keys()
=======
        if (
            "commit" in commit_diffs.keys()
>>>>>>> 994d915cd7bc9442b876e49bb35fe1e163d572ef
            and "author" in commit_diffs["commit"].keys()
            and "date" in commit_diffs["commit"]["author"].keys()
        ):
            commit_timestamp = commit_diffs["commit"]["author"]["date"]
<<<<<<< HEAD
        if commit_timestamp is not None:
            commit_instance["timestamp"] = commit_timestamp
=======
>>>>>>> 994d915cd7bc9442b876e49bb35fe1e163d572ef
        if "files" not in commit_diffs.keys():
            continue
        for file in commit_diffs["files"]:
            if "filename" not in file.keys():
                continue
            if filename in file["filename"]:
                if "patch" not in file.keys():
                    continue
                patch = file["patch"]
                diff_data = categorize_change(patch, filetype, specification)
                if diff_data is not None:
                    commit_instance["patches"].append(diff_data)
        if len(commit_instance["patches"]) > 0:
            commit_list.append(commit_instance)
    return commit_list
<<<<<<< HEAD
                
=======

>>>>>>> 994d915cd7bc9442b876e49bb35fe1e163d572ef

def get_commit_data(document, specification):
    if "commit_url" not in document.keys():
        return None
    commit_data = retry_request(document["commit_url"])
    if commit_data is not None:
        commit_data = commit_data.json()
    else:
        return None
    return get_commit_diffs(
        commit_data, document["filename"], document["extension"], specification
    )


def main():
    database = vexDB()
<<<<<<< HEAD
    collections = database.get_collections()
    for collection in collections:
        documents = database.retrieve_collection_data(collection)
        documents = list(documents)
        sample_size = min(400, len(documents))
        sample = random.sample(documents, sample_size)
        for document in tqdm(
            sample,
            desc=f"{collection}",
            total=len(sample),
            unit="documents"
        ):
            result = get_commit_data(document, collection)
            if result and len(result) > 0:
                collection = database.db.get_collection(collection)
=======
    ids = gen_doc_indexes()
    document_count = database.count_documents()
    for document, specification in tqdm(
        database.get_all_documents(),
        desc="Analyzing documents",
        total=document_count,
        unit="documents",
    ):
        if document["_id"] in ids[specification]:
            result = get_commit_data(document, specification)
            if result is not None and len(result) > 0:
                collection = database.db.get_collection(specification)
>>>>>>> 994d915cd7bc9442b876e49bb35fe1e163d572ef
                collection.update_one(
                    {"_id": document["_id"]}, {"$set": {"commit_diffs": result}}
                )


if __name__ == "__main__":
    main()
