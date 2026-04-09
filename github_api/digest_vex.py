from database import vexDB
from tqdm import tqdm
import jsonc # Helps with parsing illegal Json
from enum import Enum
import xml.etree.ElementTree as ET
import argparse
import os
from collections import defaultdict
from copy import deepcopy

class Extentions(Enum):
    JSON = 1
    XML = 2

# 3 gather vex spesific datapoints
# 3.a Average vulnerabilities per file
# 3.b Which Tools are used if any
# 3.c Spesification version (On a per spesification basis)
# 3.d databases
# 3.e Vulnerability status
# 3.f Vulnerability severity (Buckets?)
# 4 Make plots

def tools_analysis(vex, extention: Extentions, spesification: str, buckets: dict) -> dict:
    if extention == Extentions.JSON:
        if spesification == "OpenVEX" and "tooling" in vex.keys():
            buckets["OpenVEX"][vex["tooling"]] += 1
            buckets["OpenVEX"]["count"] += 1
        
        elif spesification == "CSAF" and "document" in vex.keys():
            # CSAF dosen't have a "tools" field, but a tool could be a publisher. 
            buckets["CSAF"][vex["document"]["publisher"]["name"]] += 1
            buckets["CSAF"]["count"] += 1
        
        elif (spesification == "CycloneDX"  and 
              type(vex) == dict and
              "metadata" in vex.keys() and 
              "tools" in vex["metadata"].keys() and
              len(vex["metadata"]["tools"]) != 0):
            if type(vex["metadata"]["tools"]) == dict:
                # "services"
                if "components" in vex["metadata"]["tools"].keys():
                    tools = vex["metadata"]["tools"]["components"]
                elif "services" in vex["metadata"]["tools"]:
                    tools = vex["metadata"]["tools"]["services"]
            elif type(vex["metadata"]["tools"]) == list:
                tools = vex["metadata"]["tools"]
            for tool in tools:
                if "externalReferences" in tool.keys():
                    buckets["CycloneDX"][tool["name"]] += 1
                elif "vendor" in tool.keys():
                    buckets["CycloneDX"][tool["name"]] += 1
                elif "type" in tool.keys() and tool["type"] == "application":
                    buckets["CycloneDX"][tool["name"]] += 1
                else:
                    # Services
                    # Providers
                    # framework
                    buckets["CycloneDX"][tool["name"]] += 1

                buckets["CycloneDX"]["count"] += 1
            # tools["CycloneDX"][vex["metadata"]["tools"]["name"]] = tools.setdefault(vex["metadata"]["tools"]["name"], 0) + 1
        
        elif spesification == "SPDX" and "@graph" in vex.keys():
            for entry in vex["@graph"]:
                if entry["type"] == "CreationInfo" and "createdUsing" in entry.keys():
                    for tool in entry["createdUsing"]:
                        buckets["SPDX"][tool] += 1
                        buckets["SPDX"]["count"] += 1

    elif extention == Extentions.XML:
        pass
    return buckets

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
        "--verions",
        action="store_true",
        help="Analyses the different versions of the spesifications",
    )
    parser.add_argument(
        "-db"
        "--databases",
        action="store_true",
        help="Analyses the different databases used",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Analyses the different statuses the vulnerabilites has"
    )
    parser.add_argument(
        "--severity",
        action="store_true",
        help="Analyses the severity the culnerabilites has"
    )
    parser.add_argument(
        "-p",
        "--plots",
        action="store_true",
        help="Creats plots for any analyses performed. Stored in the /plots folder"
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
        "SPDX": deepcopy(empty_dict)
        }
    
    database = vexDB()
    document_count = database.count_documents()
    errors = []
    for document, spesification in tqdm(database.get_all_documents(), desc="Analyzing documents", total=document_count, unit="documents"):
        match (document["extension"]):
            case "json" | "jsonld":
                # Cast file to dict
                try:
                    vex = jsonc.loads(document["file"], )
                except Exception as err:
                    log = {
                        "id":  document["_id"],
                        "extention": document["extension"],
                        "error": err.__str__()
                    }
                    errors.append(log)
                    continue
                # Set extention variable (enum for readability?)
                extention = Extentions.JSON
            case "xml":
                # Cast file to xml tree
                try:
                    vex = ET.fromstring(document["file"])
                except Exception as err:
                    log = {
                        "id":  document["_id"],
                        "extention": document["extension"],
                        "error": err.__str__()
                    }
                    errors.append(log)
                    continue
                # Set extention variable (enum for readability?)
                extention = Extentions.XML
            case _:
                print("Unknown extention. Skipping")
        
        # Skip schema documents
        if (document["filename"].count("schema") > 0 or
            (type(vex) == dict and "$schema" in vex.keys())):
            continue

        # Analysis
        if (args.tools or args.all):
            tools = tools_analysis(vex=vex, extention=extention, spesification=spesification, buckets=tools)
    pass


if __name__ == "__main__":
    main()