from pymongo import MongoClient
import json

class vexDB:
    def __init__(self):
        self.client = MongoClient("localhost", 27017)
        self.db = self.client.mydatabase

    def add_file_to_collection(self, collection: str, filename: str) -> None:
        collection = self.db.get_collection(collection)
        with open (filename) as f:
            json_data = json.load(f)
        collection.insert_one(json_data)

    def retrieve_collection_data(self, collection: str) -> None:
        collection = self.db.get_collection(collection)
        for item in collection.find():
            print(item)

    def clear_collection(self, collection: str) -> None:
        self.db.get_collection(collection).delete_many({})
