import random
import re

from database import vexDB
from main import retry_request
from tqdm import tqdm

random.seed("vex")

CDX_VEX_HEUR = ["vulnerabilities", "affects", "ratings", "cwes"]
CSAF_VEX_HEUR = ["vulnerabilities", "csaf_vex", "affected"]
SPDX_VEX_HEUR = ["Vulnerability"]


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
        commit_instance = {"patches": []}
        if commit is None:
            continue
        commit_diffs = retry_request(commit["url"])
        if commit_diffs is None:
            continue
        commit_diffs = commit_diffs.json()
        commit_timestamp = None
        if (
            "commit" in commit_diffs.keys()
            and "author" in commit_diffs["commit"].keys()
            and "date" in commit_diffs["commit"]["author"].keys()
        ):
            commit_timestamp = commit_diffs["commit"]["author"]["date"]
        if commit_timestamp is not None:
            commit_instance["timestamp"] = commit_timestamp
        if "files" not in commit_diffs.keys():
            continue
        for file in commit_diffs["files"]:
            if "filename" not in file.keys():
                continue
            if filename == file["filename"]:
                if "patch" not in file.keys():
                    continue
                patch = file["patch"]
                diff_data = categorize_change(patch, filetype, specification)
                if diff_data is not None:
                    commit_instance["patches"].append(diff_data)
        if len(commit_instance["patches"]) > 0:
            commit_list.append(commit_instance)
    return commit_list


def get_commit_data(document, specification):
    if "commit_url" not in document.keys():
        return None
    commit_data = retry_request(document["commit_url"])
    if commit_data is not None:
        commit_data = commit_data.json()
    else:
        return None, None
    return get_commit_diffs(
        commit_data,
        document["commit_url"].split("path=")[1],
        document["extension"],
        specification,
    ), len(commit_data)


def main():
    database = vexDB()
    collections = database.get_collections()
    for collection in collections:
        documents = database.retrieve_collection_data(collection)
        if collection == "CSAF":
            documents = [
                document
                for document in documents
                if "aquasecurity" not in document["commit_url"]
            ]
        documents = list(documents)
        sample_size = min(300, len(documents))
        sample = random.sample(documents, sample_size)
        for document in tqdm(
            sample, desc=f"{collection}", total=len(sample), unit="documents"
        ):
            try:
                result, num_commits = get_commit_data(document, collection)
                if result and len(result) > 0:
                    dbcollection = database.db.get_collection(collection)
                    dbcollection.update_one(
                        {"_id": document["_id"]}, {"$set": {"commit_diffs": result}}
                    )
                if num_commits:
                    dbcollection = database.db.get_collection(collection)
                    dbcollection.update_one(
                        {"_id": document["_id"]},
                        {"$set": {"commits_analyzed": num_commits}},
                    )
            except Exception as e:
                print(e)


if __name__ == "__main__":
    main()
