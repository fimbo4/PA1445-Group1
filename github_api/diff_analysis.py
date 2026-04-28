import random

from database import vexDB
from tqdm import tqdm

db = vexDB()
random.seed("vex")

SAMPLE_SIZE = 300  # 600






def random_document_indexes(collection_size, num_docs) -> list:
    if num_docs <= collection_size:
        return random.sample(range(collection_size), num_docs)
    else:
        return random.sample(range(collection_size), collection_size)


def gen_doc_indexes():
    ids = {"OpenVEX": [], "CSAF": [], "SPDX": [], "CycloneDX": []}
    values = {"OpenVEX": 0, "CycloneDX": 0, "CSAF": 0, "SPDX": 0}
    collections = db.get_collections()
    for collection in collections:
        doc_indexes = random_document_indexes(
            db.get_collection_size(collection), SAMPLE_SIZE
        )
        documents = db.retrieve_collection_data(collection)
        index = 0
        for document in documents:
            if index in doc_indexes:
                ids[collection].append(document["_id"])
                if "commit_diffs" in document.keys():
                    values[collection] += 1
            index += 1
    return ids, values


def main():
    ids, values = gen_doc_indexes()
    document_count = db.count_documents()
    for document, specification in tqdm(
        db.get_all_documents(),
        desc="Analyzing documents",
        total=document_count,
        unit="documents",
    ):
        # if document["_id"] in ids[specification]:
        if "commit_diffs" in document.keys():
            # values[specification] += 1
            pass

    print(values)


if __name__ == "__main__":
    main()
