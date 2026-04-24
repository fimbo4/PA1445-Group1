import argparse
from collections import defaultdict
from copy import deepcopy
from pathlib import Path
from statistics import mean, median, mode

import jsonc  # Helps with parsing illegal Json
from analysis.extentions import Extentions
from analysis.Rating import ratings_analysis
from analysis.Repository import repository_analysis
from analysis.Specification import spesification_analysis
from analysis.Status import status_analysis
from analysis.Tools import tools_analysis, tools_tables
from analysis.Vulnerability import vulnerabilities_analysis
from analysis.Vulnerability_database import database_analysis
from database import vexDB
from lxml import etree
from tqdm import tqdm


def input_arguments() -> argparse.Namespace:
    """Defines input arguments, use -h or --help to find out more."""
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--all",
        action="store_true",
        help="Performs all the different analyses",
    )
    parser.add_argument(
        "-t",
        "--tools",
        action="store_true",
        help="Analyses the tool usage",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="store_true",
        help="Analyses the different versions of the spesifications",
    )
    parser.add_argument(
        "-db",
        "--databases",
        action="store_true",
        help="Analyses the different databases used",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Analyses the different statuses the vulnerabilites has",
    )
    parser.add_argument(
        "--rating",
        action="store_true",
        help="Analyses the ratings the vulnerabilites has",
    )
    parser.add_argument(
        "-p",
        "--plots",
        action="store_true",
        help="Creats plots for any analyses performed. Stored in the /plots folder",
    )
    parser.add_argument(
        "-vuln",
        "--vulnerabilities",
        action="store_true",
        help="Analyses the mean mode and median for the number of vulnerabilities",
    )
    parser.add_argument(
        "--repo",
        action="store_true",
        help="Analyses the mean mode and median for the number of vulnerabilities",
    )

    args = parser.parse_args()
    return args


def main() -> None:
    args = input_arguments()
    empty_dict = defaultdict(int)
    tools = {
        "OpenVEX": deepcopy(empty_dict),
        "CSAF": deepcopy(empty_dict),
        "CycloneDX": deepcopy(empty_dict),
        "SPDX": deepcopy(empty_dict),
    }
    versions = deepcopy(tools)
    vulnerabilities = {"OpenVEX": [], "CSAF": [], "CycloneDX": [], "SPDX": []}
    lacks_vulnerabilities = {"OpenVEX": 0, "CSAF": 0, "CycloneDX": 0, "SPDX": 0}
    databases = deepcopy(empty_dict)
    statuses = deepcopy(tools)
    suported_ratings = {
        "CVSS": {"2": 0, "3": 0, "4": 0},
        "OWASP": 0,
        "other": [],
        "ratings": [],
        "count": 0,
    }
    ratings = {
        "OpenVEX": deepcopy(suported_ratings),
        "CSAF": deepcopy(suported_ratings),
        "CycloneDX": deepcopy(suported_ratings),
        "SPDX": deepcopy(suported_ratings),
    }
    repos = deepcopy(tools)

    database = vexDB()
    document_count = database.count_documents()
    errors = []
    non_VEX_count = 0
    non_VEX = []
    for document, specification in tqdm(
        database.get_all_documents(),
        desc="Analyzing documents",
        total=document_count,
        unit="documents",
    ):
        match (document["extension"]):
            case "json" | "jsonld":
                # Cast file to dict
                try:
                    vex = jsonc.loads(
                        document["file"],
                    )
                except Exception as err:
                    log = {
                        "id": document["_id"],
                        "extention": document["extension"],
                        "error": err.__str__(),
                    }
                    errors.append(log)
                    continue
                extention = Extentions.JSON
            case "xml":
                # Cast file to xml tree
                try:
                    vex = etree.fromstring(document["file"].encode("utf-8"))
                except Exception as err:
                    log = {
                        "id": document["_id"],
                        "extention": document["extension"],
                        "error": err.__str__(),
                    }
                    errors.append(log)
                    continue
                extention = Extentions.XML
            case _:
                print("Unknown extention. Skipping")

        # Skip schema documents
        if (
            document["filename"].count("schema") > 0
            or type(vex) == list
            or (
                type(vex) == dict
                and (specification != "CycloneDX" and specification != "CSAF")
                and "$schema" in vex.keys()
            )
        ):
            non_VEX_count += 1
            non_VEX.append({"_id": document["_id"], "filename": document["filename"]})
            continue
            # List of incorrectly skipped documents:
            # Skipped because of the name:
            # ObjectId('69c39d2cc28f54bef1261b17') - CycloneDX Confluence
            # ObjectId('69c39db1c28f54bef1261bd4') - CycloneDX Confluence
            # ObjectId('69c39e46c28f54bef1261c9c') - CycloneDX Confluence
            # ObjectId('69c39e55c28f54bef1261cb4') - CycloneDX Confluence
            # ObjectId('69c39fd1c28f54bef1261eb8') - CycloneDX Confluence
            # ObjectId('69c3a075c28f54bef1261f85') - CycloneDX Confluence
            # Skipped because it is a list:
            # ObjectId('69c3a073c28f54bef1261f81') - The GitHub list

        # Analysis
        if args.tools or args.all:
            tools = tools_analysis(
                vex=vex, extention=extention, specification=specification, buckets=tools
            )
        if args.version or args.all:
            versions = spesification_analysis(
                vex=vex,
                extention=extention,
                specification=specification,
                buckets=versions,
            )
        if args.vulnerabilities or args.all:
            vulnerabilities, lacks_vulnerabilities = vulnerabilities_analysis(
                vex=vex,
                extension=extention,
                specification=specification,
                vulnerabilities=vulnerabilities,
                lacks_vulnerabilities=lacks_vulnerabilities,
            )

        if args.databases or args.all:
            databases = database_analysis(
                vex=vex,
                extention=extention,
                specification=specification,
                buckets=databases,
            )
        if args.status or args.all:
            statuses = status_analysis(
                vex=vex,
                extention=extention,
                specification=specification,
                buckets=statuses,
            )

        if args.rating or args.all:
            ratings = ratings_analysis(
                vex=vex,
                extention=extention,
                specification=specification,
                buckets=ratings,
            )

        if args.repo or args.all:
            repos = repository_analysis(
                document=document, specification=specification, buckets=repos
            )

    if args.vulnerabilities or args.all:
        for key in vulnerabilities.keys():
            v_median = median(vulnerabilities[key])
            v_mode = mode(vulnerabilities[key])
            v_mean = mean(vulnerabilities[key])
            v_median_non_zero = median(
                [val for val in vulnerabilities[key] if val != 0]
            )
            v_mode_non_zero = mode([val for val in vulnerabilities[key] if val != 0])
            v_mean_non_zero = mean([val for val in vulnerabilities[key] if val != 0])
    if args.plots:
        file_counts = database.get_documents_per_collections()
        current_path = Path(__file__).parent
        if args.tools or args.all:
            folder = current_path / "results/tools"
            folder.mkdir(parents=True, exist_ok=True)
            tools_tables(buckets=tools, file_count=file_counts, folder=folder)
    pass


if __name__ == "__main__":
    main()
