def repository_analysis(document, specification: str, buckets: dict) -> dict:
    """
    Extracts the repository the file comes from

    Parameters
    document - the mongodb document
    specification - the specification of the current document file
    buckets - the datastructure we add the repository data to

    Returns
    buckets
    """
    commit_url = document["commit_url"]
    repo = commit_url.split("repos/")
    repo = repo[1].split("/", 2)[0] + "/" + repo[1].split("/", 2)[1]
    buckets[specification][repo] += 1
    return buckets
