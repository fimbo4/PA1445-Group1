from database import vexDB
from dateutil.parser import parse
from main import retry_request
from tqdm import tqdm


def get_timediff(commits) -> list:
    """
    The commit url lists the commits from most recent at the start and backward, so the data this returns is
    a list of the time between the most recent commit and the previous one, then the previous one and the one before that and so on in that order in the list
    """
    timediffs = []

    if not commits:
        return timediffs

    prev_time = None
    for commit in commits:
        datetime = parse(commit["commit"]["author"]["date"])
        if prev_time:
            timediff = (prev_time - datetime).days
            timediffs.append(timediff)
        prev_time = datetime

    return timediffs


def main():

    commit_results = {"OpenVEX": {}, "CSAF": {}, "CycloneDX": {}, "SPDX": {}}

    db = vexDB()
    document_count = db.count_documents()
    for document, specification in tqdm(
        db.get_all_documents(),
        desc="Analyzing documents",
        total=document_count,
        unit="documents",
    ):
        commit_url = document["commit_url"]
        repo = commit_url.split("repos/")
        repo = repo[1].split("/", 2)[0] + "/" + repo[1].split("/", 2)[1]

        if repo not in commit_results[specification].keys():
            commit_results[specification][repo] = {}
        commits = retry_request(document["commit_url"])

        if commits is not None:
            commits = commits.json()

        timediffs = get_timediff(commits)
        num_commits = 0

        if commits is not None:
            num_commits = len(commits)

        filename = document["filename"]

        if filename not in commit_results[specification][repo].keys():
            commit_results[specification][repo][filename] = {}

        commit_results[specification][repo]["timediffs"] = timediffs
        commit_results[specification][repo]["num_commits"] = num_commits

    return commit_results


if __name__ == "__main__":
    main()
