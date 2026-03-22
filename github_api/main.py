import argparse
import json
import os
from time import sleep
from typing import Generator
from math import ceil
from copy import deepcopy

import requests
import tqdm
from database import vexDB
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("GITHUB_TOKEN")

headers = {"Authorization": f"Token {TOKEN}"}

PAGE_LIMIT = 100
GITHUB_SEARCH_LIMIT = 1000
GITHUB_SIZE_LIMIT_B = 384000
INCLUDE_OPTIONAL = {"CycloneDX": True, "CSAF": True, "OpenVEX": True, "SPDX": True}


def download_file(file_url: str) -> None:
    """
    Downloads the file to the folder vex_files/.

    Parameters
    file_url - The html_url of the file to download
    """
    folder = f"vex_files"
    if not os.path.exists(folder):
        os.makedirs(folder)

    file_url = file_url.replace("https://", "https://raw.")
    file_url = file_url.replace("blob/", "")

    filename = file_url.split("/")[-1]
    filepath = f"{folder}/{filename}"

    response = retry_request(file_url)
    try:
        with open(filepath, "w") as fp:
            fp.write(response.content.decode("utf-8"))
    except:
        print(f"Decoding error for: {filename}")
        os.remove(filepath)


def add_file_to_db(database: vexDB, file_url: str, collection_name: str) -> None:
    """
    Adds the file to the database under the specified collection.

    Parameters
    database - A MongoDB database, preferably VexDB
    file_url - The html_url of the file to add
    collection_name - The name of the collection the file is to be added to
    """

    file_url = file_url.replace("https://", "https://raw.")
    file_url = file_url.replace("blob/", "")

    filename = file_url.split("/")[-1]
    filetype = filename.split(".")[-1]

    response = retry_request(file_url)
    try:
        content = response.content.decode("utf-8")
        content = {filename: content, "extension": filetype}
        database.add_file_to_collection(collection_name, content)
    except Exception as error:
        print(f"Error: {error}")


def retry_request(req: str) -> requests.Response:
    """
    Makes a GET request, and on a 4xx error sleeps.

    Parameters
    req - string contaning the url

    Return
    The response object
    """
    successful = False
    while not successful:
        try:
            response = requests.request("GET", req, headers=headers)
            if response.status_code == 200:
                return response
            elif response.status_code == 403:
                print(
                    f"{req} gave status code {response.status_code}: sleeping for 1m then retrying"
                )
                sleep(60)
            else:
                response.raise_for_status()
        except Exception as e:
            print(f"Error when making request for: {req}: {e}")
            return None


def get_commit_history(vex_file: dict) -> None:
    """
    Get's the commit history of a file from Github.

    Parameters
    vex_file - A github API file
    """
    path = vex_file["path"]
    owner = vex_file["repository"]["owner"]["login"]
    repo = vex_file["repository"]["name"]
    commit_url = f"http://api.github.com/repos/{owner}/{repo}/commits?path={path}"
    print(commit_url)


def get_search_terms() -> dict:
    """Reads the search_terms.json and returns"""
    search_file = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "search_terms.json"
    )
    search_terms = {}

    with open(search_file, "r") as st:
        search_terms = json.loads(st.read())
    return search_terms


def construct_search_code_urls(search_terms: dict) -> dict[list[dict]]:
    """
    Constructs Github Search url's based on the search terms.
    One url is constructed per search criteria and extention.

    Parameters
    search_terms - A dict contaning the search parameters

    Returns
    The search url's grouped by specification
    """
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
                search_urls[specification].append(
                    {
                        "search_url": f"{url}in:file+extension:{extention}+size:0..{GITHUB_SIZE_LIMIT_B}&per_page={PAGE_LIMIT}"
                    }
                )
    return search_urls

def change_split(url: str, range: tuple) -> str:
    start_location = url.find("size:")
    end_location = url.find("&", start_location)
    # splitter = url.find("..", start=start_location)
    new_url = f"{url[:start_location + 5]}{range[0]}..{range[1]}{url[end_location:]}"
    return new_url
    
    # ulr_parts = url.split(sep="&")
    # for thing in ulr_parts:
    #     if "size" in thing:
    #         current_range = (int(thing.split("..")[0][5:]), int(thing.split("..")[1]))
    #         break
    

def split_search(current_results: dict[list[dict]], url: str, count: int, specification: str, current_range=(0,GITHUB_SIZE_LIMIT_B)):
    """
    Splits a search into smaller searches base of the sizes of the files
    """
    new_results = deepcopy(current_results)
    splits_required = ceil(count/GITHUB_SEARCH_LIMIT)
    range_amount = (current_range[1] - current_range[0]) / splits_required

    split_ranges = []
    for i in range(splits_required):
        split_ranges.append((
            round(i*range_amount + current_range[0]),
            round((i+1)*range_amount + current_range[0])
        ))

    for new_range in split_ranges:
        new_url = change_split(url, new_range)
        response = retry_request(new_url)
        if "total_count" in response.json().keys() and response.json()["total_count"] > GITHUB_SEARCH_LIMIT:
            new_results = split_search(current_results=new_results, url=new_url, count=response.json()["total_count"], specification=specification, current_range=new_range)
        
        elif "total_count" in response.json().keys() and response.json()["total_count"] > 0:
            new_results[specification].append(
                {
                    "search_url": new_url,
                    "request": deepcopy(response)
                }
            )
    return new_results
    
    # If you want to extract the range from the url:
    # ulr_parts = url.split(sep="&")
    # for thing in ulr_parts:
    #     if "size" in thing:
    #         current_range = (int(thing.split("..")[0][5:]), int(thing.split("..")[1]))
    #         break
    
    # if "items" in count.keys():

def initial_search(search_terms: dict) -> tuple[dict[list], int]:
    """
    Performs the initial search to get the first page with results.

    Parameters
    search_terms - A dict contaning the search parameters

    Returns
    Adds the resulting request next to the search_url and
    A total count of the amount of files found
    """
    search_urls = construct_search_code_urls(search_terms)
    # search_result = deepcopy(search_urls)
    search_result = {}
    total_count = 0

    for specification, searches in search_urls.items():
        search_result[specification] = []
        for i, url in enumerate(searches):
            request = retry_request(url["search_url"])
            # search_result[specification][i]["request"] = request
            content = request.json() 
    
            if "total_count" in content.keys():
                total_count += content["total_count"]
                if content["total_count"] > GITHUB_SEARCH_LIMIT:
                    search_result = split_search(search_result, url["search_url"], content["total_count"], specification=specification)
                elif content["total_count"] > 0:
                    search_result[specification].append(
                        {
                            "search_url": url["search_url"],
                            "request": deepcopy(request)
                        }
                    )
            # try:
            # except Exception as e:
            #     print("initial_search request failed")

    return search_urls, total_count


def file_generator(pages: dict[list]) -> Generator[dict]:
    """
    Generator for looping over the search results.

    Parameters
    pages - dictionary for each spesification, containing all base searches

    Returns
    The Github representation of a file
    """
    for specification, searches in pages.items():
        for search in searches:
            for i in range(
                1, min(ceil(search["request"].json()["total_count"] / PAGE_LIMIT) + 1, 10)
            ):
                url_page = search["search_url"] + f"&page={i}"
                current_page = retry_request(url_page)
                try:
                    for item in current_page.json()["items"]:
                        yield item, specification
                except:
                    print("file_generator() request failed")


def input_arguments() -> argparse.Namespace:
    """Defines input arguments, use -h or --help to find out more."""
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-d",
        "--download",
        action="store_true",
        help="Downloads all the vex files to disk",
    )
    parser.add_argument(
        "-hs",
        "--history",
        action="store_true",
        help="Gets the commit hostory for every vex file",
    )
    parser.add_argument(
        "-db",
        "--database",
        action="store_true",
        help="Add the vex files to the database",
    )
    parser.add_argument(
        "--clear-database",
        action="store_true",
        help="Drops all the collections in the database (deletes everything)"
    )

    args = parser.parse_args()
    return args


def initiate_collections(db: vexDB, search_terms: dict):
    for spec in search_terms:
        db.create_collection(spec)


def main() -> None:
    """
    Using the Github API, it searches for the files defined in serch_terms.
    Optionaly it can:
        - Download the files to disk
        - Get the commit history
        - Add the files to the database
    """
    args = input_arguments()

    if args.clear_database or args.database:
        database = vexDB()

    if args.clear_database:
        database.drop_all()

    search_terms = get_search_terms()

    if args.database:
        initiate_collections(database, search_terms)

    pages, total_count = initial_search(search_terms)

    for vex_file, vex_specification in tqdm.tqdm(
        iterable=file_generator(pages=pages),
        total=total_count,
        desc="Fetching VEX files",
        unit="files",
    ):

        if args.download:
            download_file(vex_file["html_url"])
        if args.history:
            get_commit_history(vex_file)
        if args.database:
            add_file_to_db(database, vex_file["html_url"], vex_specification)

if __name__ == "__main__":
    main()
