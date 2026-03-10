import requests
from pymongo import MongoClient
import json
import os
from dotenv import load_dotenv
import time

load_dotenv()

TOKEN = os.getenv("GITHUB_TOKEN")

headers = {
  'Authorization': f'Token {TOKEN}'
}

specs = {
    "openvex": {
        "keywords": ["@context", "openvex", "author", "@id", "statements", "timestamp"],
        "extensions": ["json"]
    },
    "cyclonedxj": {
        "keywords": ["CycloneDX", "vulnerabilities", "specVersion"],
        "extensions": ["json"]
    },
    "cyclonedxml": {
        "keywords": ["vulnera", "http://cyclonedx.org/schema/bom/1.7"],
        "extensions": ["xml"]
    },
    "cyclonedxp": {
        "keywords": ["vulnerabilities", "spec_version", "cyclonedx"],
        "extensions": ["proto"]
    },
    "csaf": {
        "keywords": ["/vulnerabilities", "csaf_vex"],
        "extensions": ["json"]
    },
    "spdx": {
        "keywords": ["VexVulnAssessmentRelationship"],
        "extensions": ["nt", "ttl", "json", "rdf", "jsonld"]
    }
}

def download_file(file_urls: list, folder: str, response_total) -> None:
    
    with open(f"{folder}/0_results_total.json", "w") as r:
        json.dump(response_total.json(), r)

    file_id = 1

    for url in file_urls:
        url = url.replace("https://", "https://raw.")
        url = url.replace("blob/", "")

        filename = url.split("/")[-1]
        filename = str(file_id) + "_" + filename
        filepath = f"{folder}/{filename}"

        response = requests.request("GET", url, headers=headers)

        with open(filepath, "w") as fp:
            fp.write(response.content.decode("utf-8"))

        file_id += 1

def get_vex_spec_files(spec: list, specname: str, filetype: str) -> None: 

    url = "https://api.github.com/search/code?q="

    folder = f"{specname}_{filetype}"
    if not os.path.exists(folder):
        os.makedirs(folder)

    for kword in spec:
        url = url + kword + "+"
    
    url = url + "in:file+extension:" + filetype + "&per_page=100&page=1"

    response_total = requests.request("GET", url, headers=headers)
    # print(response_total)

    file_urls = []
    commit_urls = []

    for i in range(1, 2):
        url_page = url + f"&page={i}"
        try:
            response = requests.request("GET", url_page, headers=headers)
            items = response.json()["items"]
        except:
            print(f"GitHub API response: {response}")

        for item in items:
            path = item["path"]
            owner = item["repository"]["owner"]["login"]
            repo = item["repository"]["name"]
            commit_urls.append(f"http://api.github.com/repos/{owner}/{repo}/commits?path={path}")

        for item in items:
            file_urls.append(item["html_url"])

    #download_file(file_urls, folder, response_total)
    #get_commit_history(commit_urls)

def iterate_get_vex_spec(specs: dict) -> dict:
    spec_extension_and_count = {}
    for key in specs.keys():
        for extension in specs[key]["extensions"]:

            url = "https://api.github.com/search/code?q="

            for kword in specs[key]["keywords"]:
                url = url + kword + "&"
            
            url = url + "in:file+extension:" + extension + "&per_page=100&page=1"
            try:
                response = requests.request("GET", url, headers=headers).json()
                spec_extension_and_count[f"{key}_{extension}"] = response["total_count"]
            except:
                print(f"GitHub API response: {response}")
            
            time.sleep(10)

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
    with open("github_api/search_terms.json", "r") as st:
        search_terms = json.loads(st.read())
        return search_terms[spec]
    
def get_all_search_terms() -> list:
    with open("github_api/search_terms.json", "r") as st:
        search_terms = json.loads(st.read())
        return search_terms.keys()
    
def parse_search_term(spec_name: str, search_term: dict, include_optional=False) -> None:
    # need specname: str, keywords: list, filetype: str
    for filetype in search_term.keys():
            extensions = search_term[filetype]['extentions']
            keywords = search_term[filetype]['keywords']['required']
            if include_optional:
                keywords += search_term[filetype]['keywords']['optional']
            print(
f"""{spec_name}: \n
    Filetype: {filetype}\n     
    Required: {search_term[filetype]['keywords']['required']}\n
    Optional: {search_term[filetype]['keywords']['optional']}\n
    Extensions: {search_term[filetype]['extentions']}
""")
            for extension in extensions:
                print(extension, keywords, spec_name)

def iterate_all_search_terms() -> None:
    keys = get_all_search_terms()
    for key in keys:
        parse_search_term(key, get_search_term(key), False)

if __name__ == "__main__":
    #print(iterate_get_vex_spec(specs))
    #get_vex_spec_files(specs["csaf"]["keywords"], "csaf", "json")
    #try_database()
    #parse_search_term("CycloneDX", get_search_term("CycloneDX"), True)
    iterate_all_search_terms()
    #print(get_search_term("CycloneDX"))