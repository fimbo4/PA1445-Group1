import requests
import json
import os
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("GITHUB_TOKEN")

headers = {
  'Authorization': f'Token {TOKEN}'
}

openvex = ["@context", "openvex", "author", "@id", "statements", "timestamp"]
cyclonedx = ["CycloneDX", "vulnerabilities", "affects", "specVersion"]
csaf = ["/vulnerabilities" "/product_status/" "/notes"]
spdx = []

def download_file(file_urls: list, folder: str) -> None:
    file_id = 0
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

#todo: add ability to specify date for code search
def get_vex_spec_files(spec: list, specname: str, filetype) -> None: 

    url = "https://api.github.com/search/code?q="

    folder = f"{specname}_{filetype}"
    if not os.path.exists(folder):
        os.makedirs(folder)

    for kword in spec:
        url = url + kword + "+"
    
    url = url + "in:file+extension:" + filetype + "&per_page=100"

    file_urls = []

    for i in range(1, 2):
        try:
            url_page = url + f"&page={i}"
            response = requests.request("GET", url_page, headers=headers)
            for item in response.json()["items"]:
                file_urls.append(item["html_url"])
        except:
            print("GitHub API response: ")
            print(response)
    
    #download_file(file_urls, folder)
    get_commit_history(file_urls)

def get_commit_history(file_urls: list) -> None:
    # for url in file_urls:
    #     response = requests.request("GET", f"https://api.github.com/commits/{url}")
    #     print(response)
    pass
    
if __name__ == "__main__":
    get_vex_spec_files(openvex, "openvex", "json")
    #get_vex_spec_files(cyclonedx, "cyclonedx", "json")
