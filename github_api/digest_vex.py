from database import vexDB
from tqdm import tqdm
import jsonc # Helps with parsing illegal Json
from enum import Enum
import xml.etree.ElementTree as ET
import argparse

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

def tools_analysis(vex, extention: Extentions, spesification: str, tools: dict) -> dict:
    if extention == Extentions.JSON:
        if spesification == "OpenVEX" and "tooling" in vex.keys():
            tools["OpenVEX"][vex["tooling"]] = tools.setdefault(vex["tooling"], 0) + 1
            tools["OpenVEX"]["count"] = tools.setdefault("count", 0) + 1
        elif spesification == "CSAF":
            tools["CSAF"][vex["document"]["publisher"]["name"]] = tools.setdefault(vex["document"]["publisher"]["name"], 0) + 1
            tools["CSAF"]["count"] = tools.setdefault("count", 0) + 1
        elif spesification == "CycloneDX":
            pass
    elif extention == Extentions.XML:
        pass
    return tools

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
    tools = {
        "OpenVEX": {},
        "CSAF": {},
        "CycloneDX": {},
        "SPDX": {}
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
        
        # Analysis
        if (args.tools or args.all):
            tools = tools_analysis(vex=vex, extention=extention, spesification=spesification, tools=tools)
    pass

if __name__ == "__main__":
    main()