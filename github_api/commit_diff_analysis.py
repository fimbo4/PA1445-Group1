from database import vexDB
from tqdm import tqdm
from dateutil.parser import parse
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from statistics import mean, median, mode
import os

dist_directory = "distributions"
os.makedirs(dist_directory, exist_ok=True)
top_directory = "top10"
os.makedirs(top_directory, exist_ok=True)

total_changes = {
    "OpenVEX": {
        "Added": 0,
        "Removed": 0,
        "Updated": 0
    },
    "CSAF": {
        "Added": 0,
        "Removed": 0,
        "Updated": 0
    },
    "CycloneDX": {
        "Added": 0,
        "Removed": 0,
        "Updated": 0
    },
    "SPDX": {
        "Added": 0,
        "Removed": 0,
        "Updated": 0
    }
}

field_change_list = {}

def update_total_changes(document, specification):
    if "commit_diffs" in document.keys():
        for commit in document["commit_diffs"]:
            if "patches" in commit.keys():
                for patch in commit["patches"]:
                    total_changes[specification]["Added"] += len(patch["added_fields"])
                    total_changes[specification]["Removed"] += len(patch["removed_fields"])
                    total_changes[specification]["Updated"] += len(patch["updated_fields"])
            



def update_field_changes(document, specification):
    if specification not in field_change_list.keys():
        field_change_list[specification] = {"added": {}, "removed": {}, "updated": {}}
    if "commit_diffs" not in document.keys():
        return
    for commit in document["commit_diffs"]:
        if "patches" not in commit.keys():
            return
        for patch in commit["patches"]:
            for added in patch["added_fields"]:
                if added not in field_change_list[specification]["added"].keys():
                    field_change_list[specification]["added"][added] = 1
                else:
                    field_change_list[specification]["added"][added] += 1
            for removed in patch["removed_fields"]:
                if removed not in field_change_list[specification]["removed"].keys():
                    field_change_list[specification]["removed"][removed] = 1
                else:
                    field_change_list[specification]["removed"][removed] += 1
            for updated in patch["updated_fields"]:
                if updated not in field_change_list[specification]["updated"].keys():
                    field_change_list[specification]["updated"][updated] = 1
                else:
                    field_change_list[specification]["updated"][updated] += 1


def update_total_timediffs(document, specification, total_timediffs):
    if specification not in total_timediffs.keys():
        total_timediffs[specification] = []
    prev_time = None
    for commit in document["commit_diffs"]:
        datetime = parse(commit["timestamp"])
        if prev_time:
            timediff = (prev_time - datetime).days
            total_timediffs[specification].append(timediff)
        prev_time = datetime


def update_commit_sizes(document, specification, commit_sizes):
    if specification not in commit_sizes.keys():
        commit_sizes[specification] = {"Added": [], "Removed": [], "Updated": []}
    for commit in document["commit_diffs"]:
        added = 0
        removed = 0
        updated = 0
        for patch in commit["patches"]:
            added += len(patch["added_fields"])
            removed += len(patch["removed_fields"])
            updated += len(patch["updated_fields"])
        commit_sizes[specification]["Added"].append(added)
        commit_sizes[specification]["Removed"].append(removed)
        commit_sizes[specification]["Updated"].append(updated)


def main():

    commits_analyzed = {
        "OpenVEX": 0,
        "CSAF": 0,
        "SPDX": 0,
        "CycloneDX": 0
    }

    commits_kept = {
        "OpenVEX": 0,
        "CSAF": 0,
        "SPDX": 0,
        "CycloneDX": 0
    }
    
    total_timediff = {}
    commit_sizes = {}
    db = vexDB()
    document_count = db.count_documents()
    for document, specification in tqdm(
    db.get_all_documents(),
    desc="Analyzing documents",
    total=document_count,
    unit="documents",
    ):
        
        if "aquasecurity" not in document["commit_url"] and "schema" not in document["filename"]:
            if "commits_analyzed" in document.keys():
                commits_analyzed[specification] += document["commits_analyzed"]
            
            if "commit_diffs" in document.keys():
                commits_kept[specification] += len(document["commit_diffs"])
                update_total_changes(document, specification)
                update_field_changes(document, specification)
                update_total_timediffs(document, specification, total_timediff)
                update_commit_sizes(document, specification, commit_sizes)

    #print(pd.DataFrame(commits_analyzed, index=["Commits Analysed"]).to_latex(longtable=True, caption="Commits Analyzed", label="commits_analyzed"))
    #print(pd.DataFrame(commits_kept, index=["Commits Kept"]).to_latex(longtable=True, caption="Commits Kept", label="commits_kept"))
    print(pd.DataFrame.from_dict(total_changes, orient="index").to_latex(longtable=True, caption="Summary of Field Changes", label="field_changes"))
    for specification in total_timediff.keys():
        mean_time = mean(total_timediff[specification])
        median_time = median(total_timediff[specification])
        mode_time = mode(total_timediff[specification])
        total_timediff[specification] = {"Mean": mean_time, "Median": median_time, "Mode": mode_time}
    
    #print(pd.DataFrame.from_dict(total_timediff, orient="index").to_latex(longtable=True, caption="Time Between Commits", label="timediff"))

    for specification in commit_sizes.keys():
        mean_added = mean(commit_sizes[specification]["Added"])
        median_added = median(commit_sizes[specification]["Added"])
        mode_added = mode(commit_sizes[specification]["Added"])
        mean_removed = mean(commit_sizes[specification]["Removed"])
        median_removed = median(commit_sizes[specification]["Removed"])
        mode_removed = mode(commit_sizes[specification]["Removed"])
        mean_updated = mean(commit_sizes[specification]["Updated"])
        median_updated = median(commit_sizes[specification]["Updated"])
        mode_updated = mode(commit_sizes[specification]["Updated"])
        commit_sizes[specification] = {"Added (field(s))": {"Mean": mean_added, "Median": median_added, "Mode": mode_added},
                                       "Removed (field(s))": {"Mean": mean_removed, "Median": median_removed, "Mode": mode_removed},
                                       "Updated (field(s))": {"Mean": mean_updated, "Median": median_updated, "Mode": mode_updated}
                                       }

    #for specification in commit_sizes.keys():
    #    print(pd.DataFrame.from_dict(commit_sizes[specification], orient="index").to_latex(longtable=True, caption=f"{specification} Average Size of Commit Field Changes", label=f"{specification}_size"))

    #print(field_change_list["OpenVEX"]["updated"])
    #print(openvex)
    for spec in field_change_list.keys():

        for type in field_change_list[spec].keys():
            keys = []
            keynames = []
            values = []
            i = 0
            for added in dict(sorted(field_change_list[spec][type].items(), key=lambda x:x[1], reverse=True)):
                keys.append(i)
                keynames.append(added)
                i += 1
                values.append(field_change_list[spec][type][added])
            bars = plt.bar(keys, values)
            plt.xlabel(f"Fields {type}")
            plt.ylabel("Frequency")
            #plt.xticks([])
            plt.title(f"{spec} distribution of {type} fields")
            plt.tight_layout()
            # 
            filename = os.path.join(dist_directory, f"{spec}_distribution_{type}.png")
            plt.savefig(filename)
            plt.close()
            keynames = keynames[:10]
            values = values[:10]
            bars = plt.barh(keynames, values)
            plt.xlabel(f"Frequency")
            plt.ylabel(f"Fields {type}")
            plt.bar_label(bars, fmt='%d')
            plt.xlim(0, max(values) * 1.15)
            plt.title(f"{spec} top 10 fields {type}")
            plt.tight_layout()
            filename = os.path.join(top_directory, f"{spec}_top_{type}.png")
            plt.savefig(filename)
            plt.close()

        #values = values[:10] #values[-10:]
        #keys = keys[:10] #keys[-10:]
        #df = pd.DataFrame(values, index=keys)
        #latex = df.to_latex(header=False, caption=f"{spec} added fields")

    # for spec in field_change_list.keys():
    #         for type in field_change_list[spec].keys():
    #             field_change_list[spec][type] = dict(sorted(field_change_list[spec][type].items(), key=lambda x:x[1], reverse=True))
    #             df = pd.DataFrame.from_dict(field_change_list[spec][type], orient="index").to_latex(longtable=True, caption=f"All {spec} fields {type}", label=f"all_{spec}_{type}", escape=True)
    #             print(df)

if __name__ == "__main__":
    main()