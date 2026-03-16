import requests
from pymongo import MongoClient
import json
import os
from dotenv import load_dotenv
import time
from database import vexDB

load_dotenv()

TOKEN = os.getenv("GITHUB_TOKEN")

headers = {
  'Authorization': f'Token {TOKEN}'
}

INCLUDE_OPTIONAL = {"CycloneDX": True, "CSAF": True, "OpenVEX": True, "SPDX": True}

db = vexDB()

def download_file(file_urls: list, folder: str, response_total) -> None:

    file_id = 0

    for url in file_urls:
        url = url.replace("https://", "https://raw.")
        url = url.replace("blob/", "")

        filename = url.split("/")[-1]
        filename = str(file_id) + "_" + filename
        filepath = f"{folder}/{filename}"

        response = requests.request("GET", url, headers=headers)
        try: #still creates the file but content is empty
            with open(filepath, "w") as fp: 
                fp.write(response.content.decode("utf-8"))  
        except:
            print(f"Decoding error for: {filename}")
            os.remove(filepath)

        file_id += 1

def add_files_to_db(file_urls: list, folder: str) -> None:

    file_id = 0

    db.create_collection(folder)

    for url in file_urls:
        url = url.replace("https://", "https://raw.")
        url = url.replace("blob/", "")

        filename = url.split("/")[-1]
        filename = str(file_id) + "_" + filename

        response = retry_request(url)
        try:
            content = response.content.decode("utf-8")
            content = {filename: content}
            db.add_file_to_collection(folder, content)
        except Exception as error:
            print(f"Error")

        file_id += 1

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
        add_files_to_db(file_urls, f"{specname}_{filetype}")

    return vex_filetype_count

def iterate_get_vex_spec(specs: dict) -> dict:
    spec_extension_and_count = {}
    for key in specs.keys():
        for extension in specs[key]["extensions"]:

            url = "https://api.github.com/search/code?q="

            for kword in specs[key]["keywords"]:
                url = url + kword + "&"
            
            url = url + "in:file+extension:" + extension + "&per_page=100&page=1"

            # try:
            #     response = requests.request("GET", url, headers=headers).json()
            #     spec_extension_and_count[f"{key}_{extension}"] = response["total_count"]
            # except:
            #     print(f"GitHub API response: {response}")
            
            response = retry_request(url)["total_count"]
            spec_extension_and_count[f"{key}_{extension}"] = response["total_count"]

    return spec_extension_and_count


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

def get_search_term(spec: str) -> dict:
    search_terms = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'search_terms.json')
    with open(search_terms, "r") as st:
        search_terms = json.loads(st.read())
        return search_terms[spec]
    
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
       vex_filetype_count += parse_search_term(key, get_search_term(key), download, get_history, add_to_db, include_optional)
    return vex_filetype_count

if __name__ == "__main__": 
    print(iterate_all_search_terms(download=False, get_history=False, add_to_db=True, include_optional=True))