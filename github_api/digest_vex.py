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
            context = vex["@context"]
            version = context.replace("https://openvex.dev/ns/v", "")
            buckets[spesification][version] += 1
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

def database_analysis(
    vex, extention: Extentions, spesification: str, buckets: dict
) -> dict:
    # Someone is adding junk data, could be several someones
    found_vulnerability_database = False
    if extention == Extentions.JSON:
        if spesification == "OpenVEX" and "statements" in vex.keys():
            for statement in vex["statements"]:
                if type(statement) != dict:
                    continue
                if ("vulnerability" in statement.keys() 
                    and type(statement["vulnerability"]) == dict
                    and "name" in statement["vulnerability"].keys()):
                    buckets[strip_vulnarability_to_database(statement["vulnerability"]["name"])] += 1
                    found_vulnerability_database = True
                    if "aliases" in statement["vulnerability"].keys():
                        for alias in statement["vulnerability"]["aliases"]:
                            buckets[strip_vulnarability_to_database(alias)] += 1

        elif spesification == "CSAF" and "vulnerabilities" in vex.keys():
            for vulnerability in vex["vulnerabilities"]:
                if "cve" in vulnerability.keys():
                    buckets[strip_vulnarability_to_database(vulnerability["cve"])] += 1
                    found_vulnerability_database = True
                if "ids" in vulnerability.keys():
                    for id in vulnerability["ids"]:
                        if type(id) != str:
                            continue
                        buckets[strip_vulnarability_to_database(id)] += 1
                        found_vulnerability_database = True

        elif spesification == "CycloneDX" and "vulnerabilities" in vex.keys():
            for vulnerability in vex["vulnerabilities"]:
                if (type(vulnerability) == dict
                    and "id" in vulnerability.keys()):
                    buckets[strip_vulnarability_to_database(vulnerability["id"])] += 1
                    found_vulnerability_database = True

        elif spesification == "SPDX" and "@graph" in vex.keys():
            for entry in vex["@graph"]:
                if entry["type"] == "Vulnerability" and "externalIdentifier" in entry.keys():
                    for external_identifier in entry["externalIdentifier"]:
                        if external_identifier["type"] == "ExternalIdentifier" and (external_identifier["externalIdentifierType"] == "cve" or external_identifier["externalIdentifierType"] == "securityOther"):
                            buckets[strip_vulnarability_to_database(external_identifier["identifier"])] += 1
                            found_vulnerability_database = True

    elif extention == Extentions.XML:
        # _id: {"$oid": "69c3a09dc28f54bef1261fb6"}
        if spesification == "CycloneDX":
            namespace = etree.QName(vex.tag).namespace
            # namespaces = {key: vex.nsmap[key] for key in set(list(vex.nsmap.keys())) - set([None])}
            namespaces_keys = list(vex.nsmap.keys())
            for key in namespaces_keys:
                for vulnerabilities in vex.findall(f"{f"{key}:" if key else ""}vulnerabilities", namespaces=vex.nsmap):
                    for vulnerability in vulnerabilities.findall(f"{f"{key}:" if key else ""}vulnerability", namespaces=vex.nsmap):
                        for id in vulnerability.findall(f"{f"{key}:" if key else ""}id", namespaces=vex.nsmap):
                            buckets[strip_vulnarability_to_database(id.text)] += 1
                            found_vulnerability_database = True
            # for vulnerabilities in vex.findall(etree.QName(namespace, "vulnerabilities")):
            # for vulnerabilities in vex.xpath("vulnerabilities", namespaces=namespaces):
                # for vulnerability in vulnerabilities:
                #     for tool in vulnerability:
                #         for sub_element in tool:
                #             if etree.QName(sub_element.tag).localname == "name":
                #                 buckets[spesification][sub_element.text] += 1
                #                 found_tool = True

    if found_vulnerability_database:
        buckets["count"] += 1
    return buckets

def strip_vulnarability_to_database(input: str) -> str:
    # None
    # CVE-1234-1234
    # https://somelink/CVE-1234-1234
    if input == None or input.lower() == "none":
        return "NULL"
    
    first_dash = input.rfind("-")
    if first_dash == -1:
        return "INVALID"
    
    if input.startswith("http"):
        vulnerability = link_sanitation(input)
    else:
        vulnerability = input

    if vulnerability.find(":") != -1:
        # SUSE-SU-2025:10234-1
        first_half = vulnerability.split(":")[0]
        database = first_half[:first_half.rfind("-")]
    else:
        # CVE-1978-2356
        # GHSA-j223-234f-32f3
        # dsa-234567
        identifier_regex = f"[{ALPH}]{{2,7}}"
        # min_one_number = f"[{ALPH}]|[{NUM}]({ALPH}{NUM})"
        min_one_number = f"(-(?=[{ALPH}]*[{NUM}])"
        # segment_regex = f"(-[{ALPH}{NUM}]{{2,15}}){{1,3}}"
        segment_regex = f"({min_one_number}([{ALPH}{NUM}]){{2,15}}){{1,3}})"
        
        # no
        # stable
        # ocert
        database_regex = f"{identifier_regex}{segment_regex}"
        
        result = re.match(pattern=database_regex, string=vulnerability)

        # Debug regex
        dash = vulnerability.find("-")
        first_half = vulnerability[:dash]
        second_half = vulnerability[dash:]
        # (-(([a-zA-Z]*[0-9])|([0-9]))(a-zA-Z0-9){2,15}){1,3}
        # (-(?=\D*\d)(a-zA-Z0-9){2,15}){1,3}
        ident = re.match(pattern=identifier_regex, string=first_half)
        segs = re.match(pattern=segment_regex, string=second_half)
        # Debig regex

        if not result:
            return "NOT_DATABASE"
        else:
            dash = vulnerability.find("-")
            first_half = vulnerability[:dash]
            second_half = vulnerability[dash:]
            
            ident = re.match(pattern=identifier_regex, string=first_half)
            segs = re.match(pattern=segment_regex, string=second_half)
            database = ident.group(0)

    return database

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
    databases = deepcopy(empty_dict)

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
        if args.databases or args.all:
            databases = database_analysis(
                vex=vex, 
                extention=extention, 
                spesification= spesification,
                buckets=databases,
            )
    pass


if __name__ == "__main__":
    main()
