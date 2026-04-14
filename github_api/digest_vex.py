import argparse
import os
from collections import defaultdict
from copy import deepcopy
from enum import Enum
from io import StringIO

import jsonc  # Helps with parsing illegal Json
from database import vexDB
from lxml import etree
from tqdm import tqdm


class Extentions(Enum):
    JSON = 1
    XML = 2


# 3 gather vex spesific datapoints
# 3.a Average vulnerabilities per file
# 3.c Spesification version (On a per spesification basis)
# 3.d databases
# 3.e Vulnerability status
# 3.f Vulnerability severity (Buckets?)
# 4 Make plots


def tools_analysis(
    vex, extention: Extentions, spesification: str, buckets: dict
) -> dict:
    """
    Extracts the name of the tools used to generate the vex

    Parameters
    vex - the Vex file
    extention - the extention of the vex file, this is so we can handle both json and xml
    spesification - the spesification of the current Vex file
    buckets - the datastructure we add another tool to

    Returns
    buckets
    """
    found_tool = False
    if extention == Extentions.JSON:
        if spesification == "OpenVEX" and "tooling" in vex.keys():
            buckets[spesification][vex["tooling"]] += 1
            found_tool = True

        elif spesification == "CSAF" and "document" in vex.keys():
            # CSAF dosen't have a "tools" field, but a tool could be a publisher.
            buckets[spesification][vex["document"]["publisher"]["name"]] += 1
            found_tool = True

        elif (
            spesification == "CycloneDX"
            and "metadata" in vex.keys()
            and "tools"
            in vex["metadata"].keys()  # There has to be something in the tools
            and len(vex["metadata"]["tools"]) != 0
        ):

            # Handle different kind of tools
            if type(vex["metadata"]["tools"]) == dict:
                if "components" in vex["metadata"]["tools"].keys():
                    tools = vex["metadata"]["tools"]["components"]
                elif "services" in vex["metadata"]["tools"]:
                    tools = vex["metadata"]["tools"]["services"]
            elif type(vex["metadata"]["tools"]) == list:
                tools = vex["metadata"]["tools"]

            for tool in tools:
                buckets[spesification][tool["name"]] += 1
                found_tool = True

        elif spesification == "SPDX" and "@graph" in vex.keys():
            for entry in vex["@graph"]:
                if entry["type"] == "CreationInfo" and "createdUsing" in entry.keys():
                    for tool in entry["createdUsing"]:
                        buckets[spesification][tool] += 1
                        found_tool = True

    elif extention == Extentions.XML:
        if spesification == "CycloneDX":
            namespace = etree.QName(vex.tag).namespace
            for metadata in vex.findall(etree.QName(namespace, "metadata")):
                for tools in metadata.findall(etree.QName(namespace, "tools")):
                    for tool in tools:
                        for sub_element in tool:
                            if etree.QName(sub_element.tag).localname == "name":
                                buckets[spesification][sub_element.text] += 1
                                found_tool = True
    if found_tool:
        buckets[spesification]["count"] += 1
    return buckets


def spesification_analysis(
    vex, extention: Extentions, spesification: str, buckets: dict
) -> dict:
    found_spesification = False
    if extention == Extentions.JSON:
        if spesification == "OpenVEX" and "@context" in vex.keys():
            buckets[spesification][vex["@context"]] += 1
            found_spesification = True

        elif spesification == "CSAF" and "document" in vex.keys():
            buckets[spesification][vex["document"]["csaf_version"]] += 1
            found_spesification = True

        elif spesification == "CycloneDX" and "specVersion" in vex.keys():

            buckets[spesification][vex["specVersion"]] += 1
            found_spesification = True

        elif spesification == "SPDX" and "@graph" in vex.keys():
            for entry in vex["@graph"]:
                if entry["type"] == "CreationInfo" and "specVersion" in entry.keys():
                    buckets[spesification][entry["specVersion"]] += 1
                    found_spesification = True

    elif extention == Extentions.XML:
        if spesification == "CycloneDX":
            namespace = etree.QName(vex.tag).namespace
            version = namespace.replace("http://cyclonedx.org/schema/bom/", "")
            buckets[spesification][version] += 1
            found_spesification = True

    if found_spesification:
        buckets[spesification]["count"] += 1
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
        "--version",
        action="store_true",
        help="Analyses the different versions of the spesifications",
    )
    parser.add_argument(
        "-db" "--databases",
        action="store_true",
        help="Analyses the different databases used",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Analyses the different statuses the vulnerabilites has",
    )
    parser.add_argument(
        "--severity",
        action="store_true",
        help="Analyses the severity the culnerabilites has",
    )
    parser.add_argument(
        "-p",
        "--plots",
        action="store_true",
        help="Creats plots for any analyses performed. Stored in the /plots folder",
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

    database = vexDB()
    document_count = database.count_documents()
    errors = []
    non_VEX_count = 0
    non_VEX = []
    for document, spesification in tqdm(
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
                and (spesification != "CycloneDX" and spesification != "CSAF")
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
                vex=vex, extention=extention, spesification=spesification, buckets=tools
            )
        if args.version or args.all:
            versions = spesification_analysis(
                vex=vex,
                extention=extention,
                spesification=spesification,
                buckets=versions,
            )
    pass


if __name__ == "__main__":
    main()
