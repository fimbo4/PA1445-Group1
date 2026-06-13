from database import vexDB
import random
import json

random.seed("vex")

SAMPLE_SIZE = 268

commit_list = []
commits_len = 0

db = vexDB()
commits = 0
collections = db.get_collections()
for collection in collections:
    if collection == "OpenVEX":
        continue
    documents = db.retrieve_collection_data(collection)
    for document in documents:
        if "commit_diffs" in document.keys():
        #print(document["commit_url"].split("/")[-1])
            commits_len += len(document["commit_diffs"])
            for commit in document["commit_diffs"]:
                commits += 1
                commit_list.append(commit)

samples = random.sample(commit_list, SAMPLE_SIZE)

to_write = []
commit_num = 0
for sample in samples:
    to_write.append({f"commit_{commit_num}": sample["patches"], "is_vex": 0}) #1 = yes, 2 = maybe? 3 = no
    commit_num += 1

with open("commits_to_verify.json", "w") as ctv:
    json.dump(to_write, ctv)

stati = ["affects", "affected", "unaffected", "unknown", "status", "fixed", "not_affected", "under_investigation"]
vulns = ["vulnerabilities", "vulnerability"]

has_status = 0
has_vulnerability = 0
has_both = 0
has_none = 0

print(commits)
print(len(commit_list))
print(commits_len)

for commit in commit_list:
    commit_status = False
    commit_vuln = False
    for fields in commit["patches"]:
        for fieldtype in fields.keys():
            for stat in stati:
                if stat in fields[fieldtype]:
                    commit_status = True
            for vuln in vulns:
                if vuln in fields[fieldtype]:
                    commit_vuln = True

    if commit_status and commit_vuln:
        has_both += 1
    elif commit_status and not commit_vuln:
        has_status += 1
    elif commit_vuln and not commit_status:
        has_vulnerability += 1
    else:
        has_none += 1

with open("commit_discard_reasons.json") as cdr:
    discard_reasons = json.load(cdr)
    cdr.close()

total_discards = 0
for spec in discard_reasons.keys():
    print(spec, "----------------------------------------")
    for reason in discard_reasons[spec]:
        if type(discard_reasons[spec][reason]) == int: #and not reason.endswith("_failure"):
            print(reason, discard_reasons[spec][reason])
            total_discards += discard_reasons[spec][reason]

print("total_discards: ", total_discards)

print(f"has a status: {has_status}", f"has a vulnerability: {has_vulnerability}", f"has both: {has_both}", f"has neither: {has_none}")
print(len(commit_list))
                