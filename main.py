import requests
import json
import os

url = "https://api.github.com/search/code?q=@context+statements+timestamp+in:file+language:json"

headers = {
  'Authorization': 'Token <insert token here>'
}

vex_folder = "vex_files"
if not os.path.exists(vex_folder):
    os.makedirs(vex_folder)

response = requests.request("GET", url, headers=headers)

data = response.json()

with open("data.json", "w") as f:
    json.dump(data, f)
    
with open("data.json", "r") as f: 
    data = json.load(f)

with open("html_urls.txt", "w") as f:    
    counter = 0
    for item in data["items"]:
        f.write(item["html_url"] + "\n")
        url = item["html_url"]
        rawurl = url.replace("https://", "https://raw.")
        rawurl = rawurl.replace("blob/", "")
        response = requests.request("GET", rawurl, headers=headers)   
        filename = url.split("/")[-1]
        filename = str(counter) + "_" + filename
        filepath = f"vex_files/{filename}"
        with open(filepath, "w") as fp:
            json.dump(response.json(), fp)
        counter += 1