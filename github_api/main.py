import requests
from pymongo import MongoClient
import json
import os
from dotenv import load_dotenv
import time
from database import vexDB
import tqdm
from typing import Generator
import argparse

load_dotenv()

TOKEN = os.getenv("GITHUB_TOKEN")

headers = {
  'Authorization': f'Token {TOKEN}'
}

PAGE_LIMIT = 100
INCLUDE_OPTIONAL = {"CycloneDX": True, "CSAF": True, "OpenVEX": True, "SPDX": True}

def download_file(file_url: str) -> None:
    folder = f"vex_files"
    if not os.path.exists(folder):
        os.makedirs(folder)

    file_url = file_url.replace("https://", "https://raw.")
    file_url = file_url.replace("blob/", "")

    filename = file_url.split("/")[-1]
    filepath = f"{folder}/{filename}"

    response = retry_request(file_url)
    try: #still creates the file but content is empty
        with open(filepath, "w") as fp: 
            fp.write(response.content.decode("utf-8"))  
    except:
        print(f"Decoding error for: {filename}")
        os.remove(filepath)

def add_file_to_db(database: vexDB, file_url: str, collection_name: str) -> None:

    database.create_collection(collection_name)

    file_url = file_url.replace("https://", "https://raw.")
    file_url = file_url.replace("blob/", "")

    filename = file_url.split("/")[-1]

    response = retry_request(file_url)
    try:
        content = response.content.decode("utf-8")
        content = {filename: content}
        database.add_file_to_collection(collection_name, content)
    except Exception as error:
        print(f"Error")

def retry_request(req: str) -> requests.Response: 
    successful = False
    while(not successful):
        try:
            response = requests.request("GET", req, headers=headers)
            response.raise_for_status()
            successful = True
        except requests.exceptions.RequestException:
            print(f"{req} gave status code {response.status_code}: sleeping for 1m then retrying")
            time.sleep(60)
        except Exception as e:
            print(f"Error when making request for: {req}: {e}")
    return response

def get_github_vex_files(spec: list, specname: str, filetype: str, extension: str, download: bool, get_history: bool, add_to_db: bool) -> list: 
    vex_filetype_count = []

    url = "https://api.github.com/search/code?q="

    if download:
        folder = f"{specname}_{filetype}"
        if not os.path.exists(folder):
            os.makedirs(folder)

    for kword in spec:
        url = f"{url}{kword}+"
    
    url = f"{url}in:file+extension:{extension}&per_page=100"
    response_total = retry_request(url)
    
    try:
        vex_filetype_count.append({f"{specname}-ft:{filetype}-ext:{extension}": response_total.json()["total_count"]})
    except:
        print("Failed to get total count")

    file_urls = []
    commit_urls = []

    for i in range(1, 2): #how many pages you want to search'
        url_page = url + f"&page={i}"
        
        items = retry_request(url_page)
        try:
            items = items.json()["items"]
        except:
            print("Request did not have attribute 'items': skipping")
            break

        for item in items:
            path = item["path"]
            owner = item["repository"]["owner"]["login"]
            repo = item["repository"]["name"]
            commit_urls.append(f"http://api.github.com/repos/{owner}/{repo}/commits?path={path}")

        for item in items:
            file_urls.append(item["html_url"])

    if download:
        download_file(file_urls, folder, response_total)
    if get_history:
        get_commit_history(commit_urls)
    if add_to_db:
        add_file_to_db(file_urls, f"{specname}_{filetype}")

    return vex_filetype_count

def get_commit_history(commit_urls: list) -> None:
    for commit in commit_urls:
        print(commit)

def try_database() -> None:
    try:
        client = MongoClient("mongo", 27017)
        db = client.mydatabaase
        print("successful connection")
    except:
        print("failed to connect")

def get_search_terms() -> dict:
    search_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'search_terms.json')
    search_terms = {}

    with open(search_file, "r") as st:
        search_terms = json.loads(st.read())
    return search_terms
    
def get_all_search_terms() -> list:
    search_terms = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'search_terms.json')
    with open(search_terms, "r") as st:
        search_terms = json.loads(st.read())
        return search_terms.keys()
    
def parse_search_term(spec_name: str, search_term: dict, download: bool, get_history: bool, add_to_db: bool, include_optional: bool) -> list:
    vex_filetype_count = []
    for filetype in search_term.keys():
        extensions = search_term[filetype]['extentions']
        keywords = search_term[filetype]['keywords']['required']
        if include_optional:
            keywords += search_term[filetype]['keywords']['optional']

        for extension in extensions:
            vex_filetype_count += get_github_vex_files(keywords, spec_name, filetype, extension, download, get_history, add_to_db)
    return vex_filetype_count

def iterate_all_search_terms(download: bool, get_history: bool, add_to_db: bool, include_optional: bool) -> list:
    vex_filetype_count = []
    keys = get_all_search_terms()
    for key in keys:
       vex_filetype_count += parse_search_term(key, get_search_terms(key), download, get_history, add_to_db, include_optional)
    return vex_filetype_count


def construct_search_code_urls(search_terms: dict) -> dict[list[dict]]:
    search_urls = {}
    base_url = "https://api.github.com/search/code?q="
    url = base_url

    for specification, content in search_terms.items():
        search_urls[specification] = []
        for _, type in content.items():
            url = base_url
            for keyword in type["keywords"]["required"]:
                url = f"{url}{keyword}+"
            if INCLUDE_OPTIONAL[specification]:
                for keyword in type["keywords"]["optional"]:
                    url = f"{url}{keyword}+"
            for extention in type["extentions"]:
                search_urls[specification].append({"search_url": f"{url}in:file+extension:{extention}&per_page={PAGE_LIMIT}"})
    return search_urls
        
            
def initial_search(search_terms: dict) -> tuple[dict[list], int]:
    search_results = construct_search_code_urls(search_terms)
    count = 0
    for specification, content in search_results.items():
        for url in content:
            request = retry_request(url["search_url"])
            url["request"] = request
            count += request.json()["total_count"]
    
    return search_results, count

def file_generator(pages) -> Generator[dict]:
    for specification, searches in pages.items():
        for search in searches:
            for i in range(1, (search["request"].json()["total_count"] % PAGE_LIMIT) + 2):
                url_page = search["search_url"] + f"&page={i}"
                current_page = retry_request(url_page)

                for item in current_page.json()["items"]:
                    yield item

def input_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    
    parser.add_argument("-d", "--download", action="store_true", help="Downloads all the vex files to disk")
    parser.add_argument("-hs", "--history", action="store_true", help="Gets the commit hostory for every vex file")
    parser.add_argument("-db", "--database", action="store_true", help="Add the vex files to the database")
    # include_optional

    args = parser.parse_args()
    return args

def main() -> None:
    args = input_arguments()
    search_terms = get_search_terms()
    pages, total_count = initial_search(search_terms)
    
    for vex_file in tqdm.tqdm(iterable=file_generator(pages=pages), total=total_count, desc="description of what i'm doing", unit="file"):
        pass
        # if download:
        #     download_file(file_urls, folder, response_total)
        # if get_history:
        #     get_commit_history(commit_urls)
        # if add_to_db:
        #     add_files_to_db(file_urls, f"{specname}_{filetype}")
        
    # Generators!
    


if __name__ == "__main__": 
    main()
    # print(iterate_all_search_terms(download=False, get_history=False, add_to_db=True, include_optional=True))