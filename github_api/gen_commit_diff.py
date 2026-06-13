import random
import re
import json

from collections import Counter
from database import vexDB
from main import retry_request
from tqdm import tqdm
from verify_vex import verify_vex

random.seed("vex")

CDX_VEX_HEUR = ["vulnerabilities", "ratings", "cwes", "affects", "affected", "unaffected", "unknown", "status"]
CSAF_VEX_HEUR = ["vulnerabilities", "csaf_vex", "fixed", "affected", "not_affected", "under_investigation"]
SPDX_VEX_HEUR = ["Vulnerability"]

commit_discard_reason = {
    "CSAF": {
        "commit_not_found": 0,
        "diff_request_failure": 0,
        "empty_commit_instances": 0,
        "diff_key_files_missing": 0,
        "no_vex_commits": 0,
        "filename_not_in_commit": 0,
        "history_request_failure": 0,
        "repos": []
    },
    "CycloneDX": {
        "commit_not_found": 0,
        "diff_request_failure": 0,
        "empty_commit_instances": 0,
        "diff_key_files_missing": 0,
        "no_vex_commits": 0,
        "filename_not_in_commit": 0,
        "history_request_failure": 0,
        "repos": []
    },
    "OpenVEX": {
        "commit_not_found": 0,
        "diff_request_failure": 0,
        "empty_commit_instances": 0,
        "diff_key_files_missing": 0,
        "no_vex_commits": 0,
        "filename_not_in_commit": 0,
        "history_request_failure": 0,
        "repos": []
    },   
    "SPDX": {
        "commit_not_found": 0,
        "diff_request_failure": 0,
        "empty_commit_instances": 0,
        "diff_key_files_missing": 0,
        "no_vex_commits": 0,
        "filename_not_in_commit": 0,
        "history_request_failure": 0,
        "repos": []
    }
}

analysed = {
    "OpenVEX": 0,
    "CSAF": 0,
    "CycloneDX": 0,
    "SPDX": 0
}

def parse_tags(line):
    tags = re.findall(r"</?[^>]+>", line)
    clean_tags = []
    opening_tags = []
    closing_tags = []
    for tag in tags:
        tag = tag.split(" ", 1)
        if len(tag) > 1:
            tag = tag[0] + ">"
            clean_tags.append(tag)
        else:
            tag = tag[0]
            clean_tags.append(tag)
    tags = clean_tags
    for tag in tags:
        if "</" not in tag:
            identifier = tag.strip("<>/").split()[0]
            opening_tags.append(identifier)
        else:
            identifier = tag.strip("<>/").split()[0]
            closing_tags.append(identifier)
    matches = list(Counter(opening_tags) & Counter(closing_tags))
    opening_tags = list(Counter(opening_tags) - Counter(matches))
    closing_tags = list(Counter(closing_tags) - Counter(matches))
    tags = matches + opening_tags + closing_tags
    return tags  


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
            added_keys += parse_tags(line)

        for line in remov_lines:
            remov_keys += parse_tags(line)

    updated_keys = list(Counter(added_keys) & Counter(remov_keys))
    added_keys = list(Counter(added_keys) - Counter(updated_keys))
    remov_keys = list(Counter(remov_keys) - Counter(updated_keys))
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


def get_commit_diffs(commit_data, filename, filetype, specification, commit_url):
    commit_list = []
    for commit in commit_data:
        commit_instance = {"patches": []}
        if commit is None:
            commit_discard_reason[specification]["commit_not_found"] += 1
            commit_discard_reason[specification]["repos"].append({"repo": commit_url, "reason": "commit_not_found"})
            continue
        commit_diffs = retry_request(commit["url"])
        if commit_diffs is None:
            commit_discard_reason[specification]["diff_request_failure"] += 1
            commit_discard_reason[specification]["repos"].append({"repo": commit_url, "reason": "diff_request_failure"})
            continue
        commit_diffs = commit_diffs.json()
        commit_timestamp = None
        if (
            "commit" in commit_diffs.keys()
            and "author" in commit_diffs["commit"].keys()
            and "date" in commit_diffs["commit"]["author"].keys()
        ):
            commit_timestamp = commit_diffs["commit"]["author"]["date"]
        if "files" not in commit_diffs.keys():
            commit_discard_reason[specification]["diff_key_files_missing"] += 1
            commit_discard_reason[specification]["repos"].append({"repo": commit_url, "reason": "diff_key_files_missing"})
            continue
        file_mentioned = False
        for file in commit_diffs["files"]:
            if "filename" not in file.keys():
                continue
            if file["filename"] == filename:
                file_mentioned = True
                if "patch" not in file.keys():
                    continue
                patch = file["patch"]
                diff_data = categorize_change(patch, filetype, specification)
                if diff_data is not None:
                    commit_instance["patches"].append(diff_data)
        if not file_mentioned:
            commit_discard_reason[specification]["filename_not_in_commit"] += 1
            commit_discard_reason[specification]["repos"].append({"repo": commit_url, "reason": "filename_not_in_commit"})
        if commit_timestamp is not None and file_mentioned:
            commit_instance["timestamp"] = commit_timestamp
        if len(commit_instance["patches"]) > 0:
            commit_list.append(commit_instance)
        if file_mentioned and not (len(commit_instance["patches"]) > 0):
            commit_discard_reason[specification]["empty_commit_instances"] += 1
            commit_discard_reason[specification]["repos"].append({"repo": commit_url, "reason": "empty_commit_instance"})
        try:
            analysed[specification] += 1
        except Exception as e:
            print(e)
    return commit_list


def get_commit_data(document, specification):
    if "commit_url" not in document.keys():
        return None, None
    commit_data = retry_request(document["commit_url"])
    if commit_data is not None:
        commit_data = commit_data.json()
    else:
        commit_discard_reason[specification]["history_request_failure"] += 1
        commit_discard_reason[specification]["repos"].append({"repo": document["commit_url"], "reason": "history_request_failure"})
        return None, None
    return get_commit_diffs(
        commit_data,
        document["commit_url"].split("path=")[1],
        document["extension"],
        specification,
        document["commit_url"]
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
                if "aquasecurity" not in document["commit_url"] and "schema" not in document["filename"]
            ]
        if collection == "OpenVEX":
            documents = [
                document for document in documents if "ubuntu-security-notices" not in document["commit_url"] and "schema" not in document["filename"]
            ]
        documents = [
            document for document in documents if verify_vex(document, collection)
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
    print(commit_discard_reason)
    print(analysed)
    try:
        with open("commit_discard_reasons.json", "w") as cdr:
            json.dump(commit_discard_reason, cdr)
        with open("analysed.json", "w") as anlysd:
            json.dump(analysed, anlysd)
    except Exception as e:
        print(e)
