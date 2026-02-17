from pymongo import MongoClient
import json

client = MongoClient("localhost", 27017)

db = client.mydatabase

def add_file_to_collection(collection: str, filename: str) -> None:
    collection = db.get_collection(collection)
    with open (filename) as f:
        json_data = json.load(f)
    collection.insert_one(json_data)

def retrieve_collection_data(collection: str) -> None:
    collection = db.get_collection(collection)
    for item in collection.find():
        print(item)

def clear_collection(collection: str) -> None:
    db.get_collection(collection).delete_many({})

add_file_to_collection("openvex_json", "openvex_json/0_dockle.openvex.json")
retrieve_collection_data("openvex_json")
clear_collection("openvex_json")