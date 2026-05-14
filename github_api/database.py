from typing import Generator

from pymongo import MongoClient


class vexDB:
    def __init__(self):
        self.client = MongoClient("mongo", 27017)
        self.db = self.client["Vex"]

    def create_collection(self, collection: str) -> None:
        try:
            self.db.create_collection(collection)
        except:
            print("collection already exists")

    def add_file_to_collection(self, collection: str, contents: dict) -> None:
        try:
            collection = self.db.get_collection(collection)
            collection.insert_one(contents)
        except:
            print(f"Failed to add file to {collection}")

    def retrieve_collection_data(self, collection: str) -> Generator[dict]:
        collection = self.db.get_collection(collection)
        for item in collection.find(no_cursor_timeout=True).sort("_id", 1):
            yield item

    def get_all_documents(self) -> Generator[(dict, str)]:
        collections = self.get_collections()
        for collection in collections:
            for document in self.retrieve_collection_data(collection):
                yield document, collection

    def get_collections(self) -> list[str]:
        filter = {
            "name": {"$regex": r"^(?!system\.)"}
        }  # Ignores the system collections
        collections = self.db.list_collection_names(filter=filter)
        return sorted(collections)

    def get_documents_per_collections(self) -> dict:
        collections = self.get_collections()
        counters = dict(name=collections)
        for collection in collections:
            counters[collection] = self.db.get_collection(collection).count_documents(
                filter={}
            )
        return counters

    def get_collection_size(self, collection: str) -> int:
        return self.db.get_collection(collection).count_documents(filter={})

    def count_documents(self) -> int:
        collections = self.get_collections()
        count = 0
        for collection in collections:
            count += self.db.get_collection(collection).count_documents(filter={})
        return count

    def clear_collection(self, collection: str) -> None:
        self.db.get_collection(collection).delete_many({})

    def drop_all(self) -> None:
        for collection in self.db.list_collection_names():
            self.db.drop_collection(collection)
