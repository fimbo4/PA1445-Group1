import requests
import json
import os
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("GITHUB_TOKEN")

url = "https://api.github.com/search/code?q=@context+openvex+author+@id+statements+timestamp+in:file+language:json"

headers = {
  'Authorization': f'Token {TOKEN}'
}

openvex = ["@context", "openvex", "author", "@id", "statements", "timestamp"]

def get_vex_spec_files(spec: list, specname: str, filetype: str) -> None: 

    url = "https://api.github.com/search/code?q="

    folder = f"{specname}_{filetype}"
    if not os.path.exists(folder):
        os.makedirs(folder)

    for kword in spec:
        url = url + kword + "+"
    
    url = url + "in:file+language:" + filetype + "&per_page=100"

    file_urls = []

    for i in range(1, 10):
        try:
            url_page = url + f"&page={i}"
            response = requests.request("GET", url_page, headers=headers)
            for item in response.json()["items"]:
                file_urls.append(item["html_url"])
        except:
            print("GitHub API response: ")
            print(response)
    
    print(len(file_urls))
    

if __name__ == "__main__":
    get_vex_spec_files(openvex, "openvex", "json")

# vex_folder = "vex_files"
# if not os.path.exists(vex_folder):
#     os.makedirs(vex_folder)

# response = requests.request("GET", url, headers=headers)

# data = response.json()

# with open("data.json", "w") as f:
#     json.dump(data, f)
    
# with open("data.json", "r") as f: 
#     data = json.load(f)

# with open("html_urls.txt", "w") as f:    
#     counter = 0
#     for item in data["items"]:
#         f.write(item["html_url"] + "\n")
#         url = item["html_url"]
#         rawurl = url.replace("https://", "https://raw.")
#         rawurl = rawurl.replace("blob/", "")
#         response = requests.request("GET", rawurl, headers=headers)   
#         filename = url.split("/")[-1]
#         filename = str(counter) + "_" + filename
#         filepath = f"vex_files/{filename}"
#         with open(filepath, "w") as fp:
#             json.dump(response.json(), fp)
#         counter += 1