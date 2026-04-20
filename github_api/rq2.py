import random
from database import vexDB
from main import retry_request
from statistics import mean

random.seed("vex")

#get 100 random files from db and count number of commits they have

def random_document_indexes(collection_size, num_docs) -> list:
    if num_docs <= collection_size:
        return random.sample(range(collection_size), num_docs)
    else:
        return random.sample(range(collection_size), collection_size)


def main():
    db = vexDB()

    collections = db.get_collections()
    total_commits = 0
    num_commits_list = []
    for collection in collections:
        documents = db.retrieve_collection_data(collection)
        doc_indexes = random_document_indexes(db.get_collection_size(collection), 100)
        index = 0
        counter = 0
        for document in documents:
            if index in doc_indexes:
                #print(f"{collection}-{counter} : {document["commit_url"]}")
                response = retry_request(document["commit_url"])
                #print(len(response.json()))
                if response is not None:
                    total_commits += len(response.json())
                    num_commits_list.append(len(response.json()))
                    for item in response.json():
                        print(item["html_url"])
                        #input("Continue?")
                    #print(counter)
                    counter += 1
            index += 1
    print(f"Number of commits: {total_commits}, average number of commits {mean(num_commits_list)}")
    

if __name__ == "__main__":
    main()