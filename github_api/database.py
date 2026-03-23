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

    def retrieve_collection_data(self, collection: str) -> None:
        collection = self.db.get_collection(collection)
        for item in collection.find():
            print(item)

    def clear_collection(self, collection: str) -> None:
        self.db.get_collection(collection).delete_many({})

    def drop_all(self) -> None:
        for collection in self.db.list_collection_names():
            self.db.drop_collection(collection)
