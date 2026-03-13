from pymongo import MongoClient

class vexDB:
    def __init__(self):
        self.client = MongoClient("mongo", 27017)
        self.db = self.client.mydatabase

    def create_collection(collection: str) -> None:
        pass

    def add_file_to_collection(self, collection: str, contents: str) -> None:
        collection = self.db.get_collection(collection)
        collection.insert_one(contents)

    def retrieve_collection_data(self, collection: str) -> None:
        collection = self.db.get_collection(collection)
        for item in collection.find():
            print(item)

    def clear_collection(self, collection: str) -> None:
        self.db.get_collection(collection).delete_many({})
