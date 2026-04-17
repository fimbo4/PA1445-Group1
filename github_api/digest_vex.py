import argparse
import os
import re
from collections import defaultdict
from copy import deepcopy
from enum import Enum
from io import StringIO
from statistics import mean, median, mode

import jsonc  # Helps with parsing illegal Json
from database import vexDB
from lxml import etree
from tqdm import tqdm

# Regex constants
ALPH = "a-zA-Z"
NUM = "0-9"


# Source - https://stackoverflow.com/a/68400507
# Posted by Mark, modified by community. See post 'Timeline' for change history
# Retrieved 2026-04-17, License - CC BY-SA 4.0


# We could also do class Finger(IntEnum) its equivalent.
class Status(int, Enum):
    def __new__(cls, value, label):
        # Initialise an instance of the Finger enum class
        obj = int.__new__(cls, value)
        # Calling print(type(obj)) returns <enum 'Finger'>
        # If we don't set the _value_ in the Enum class, an error will be raised.
        obj._value_ = value
        # Here we add an attribute to the finger class on the fly.
        # One may want to use setattr to be more explicit; note the python docs don't do this
        obj.label = label
        return obj

    FIXED = (3, "FIXED")
    AFFECTED = (2, "AFFECTED")
    NOT_AFFECTED = (1, "NOT_AFFECTED")
    UNDER_INVESTIGATION = (0, "UNDER_INVESTIGATION")
    UNKNOWN = (-1, "UNKNOWN")

    @classmethod
    def from_str(cls, input_str):
        for finger in cls:
            if finger.label == input_str:
                return finger
        raise ValueError(f"{cls.__name__} has no value matching {input_str}")


class Extentions(Enum):
    JSON = 1
    XML = 2


# 3 gather vex spesific datapoints
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
    """
    Extracts the version number of the spesification

    Parameters
    vex - the Vex file
    extention - the extention of the vex file, this is so we can handle both json and xml
    spesification - the spesification of the current Vex file
    buckets - the datastructure we add another version number to

    Returns
    buckets
    """
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
    """
    Extracts the name of the databases the vulnerabilites come from

    Parameters
    vex - the Vex file
    extention - the extention of the vex file, this is so we can handle both json and xml
    spesification - the spesification of the current Vex file
    buckets - the datastructure we add the databases to

    Returns
    buckets
    """
    found_vulnerability_database = False
    if extention == Extentions.JSON:
        if spesification == "OpenVEX" and "statements" in vex.keys():
            for statement in vex["statements"]:
                if type(statement) != dict:
                    continue
                if (
                    "vulnerability" in statement.keys()
                    and type(statement["vulnerability"]) == dict
                    and "name" in statement["vulnerability"].keys()
                ):
                    buckets[
                        strip_vulnarability_to_database(
                            statement["vulnerability"]["name"]
                        )
                    ] += 1
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
                if type(vulnerability) == dict and "id" in vulnerability.keys():
                    buckets[strip_vulnarability_to_database(vulnerability["id"])] += 1
                    found_vulnerability_database = True

        elif spesification == "SPDX" and "@graph" in vex.keys():
            for entry in vex["@graph"]:
                if (
                    entry["type"] == "Vulnerability"
                    and "externalIdentifier" in entry.keys()
                ):
                    for external_identifier in entry["externalIdentifier"]:
                        if external_identifier["type"] == "ExternalIdentifier" and (
                            external_identifier["externalIdentifierType"] == "cve"
                            or external_identifier["externalIdentifierType"]
                            == "securityOther"
                        ):
                            buckets[
                                strip_vulnarability_to_database(
                                    external_identifier["identifier"]
                                )
                            ] += 1
                            found_vulnerability_database = True

    elif extention == Extentions.XML:
        if spesification == "CycloneDX":
            namespaces_keys = list(vex.nsmap.keys())
            for key in namespaces_keys:
                for vulnerabilities in vex.findall(
                    f"{f"{key}:" if key else ""}vulnerabilities", namespaces=vex.nsmap
                ):
                    for vulnerability in vulnerabilities.findall(
                        f"{f"{key}:" if key else ""}vulnerability", namespaces=vex.nsmap
                    ):
                        for id in vulnerability.findall(
                            f"{f"{key}:" if key else ""}id", namespaces=vex.nsmap
                        ):
                            buckets[strip_vulnarability_to_database(id.text)] += 1
                            found_vulnerability_database = True

    if found_vulnerability_database:
        buckets["count"] += 1
    return buckets


def strip_vulnarability_to_database(input: str) -> str:
    """Tries to extract the datbase from the input"""
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
        first_half = vulnerability.split(":")[0]
        database = first_half[: first_half.rfind("-")]
    else:
        identifier_regex = f"[{ALPH}]{{2,7}}"
        min_one_number = f"(-(?=[{ALPH}]*[{NUM}])"
        segment_regex = f"({min_one_number}([{ALPH}{NUM}]){{2,15}}){{1,3}})"
        database_regex = f"{identifier_regex}{segment_regex}"
        # [a-zA-Z]{2,7}((-(?=[a-zA-Z]*[0-9])([a-zA-Z0-9]){2,15}){1,3})

        result = re.match(pattern=database_regex, string=vulnerability)
        if not result:
            return "NOT_DATABASE"
        else:
            dash = vulnerability.find("-")
            first_half = vulnerability[:dash]

            ident = re.match(pattern=identifier_regex, string=first_half)
            database = ident.group(0)

    return database


def link_sanitation(vulnerability: str) -> str:
    """Removes the link from the vulnerablility"""
    seperators = [
        "/",
        ",",
        "=",
        "?",
        ":",
    ]
    counter = 0
    for char in reversed(vulnerability):
        if char in seperators:
            break
        else:
            counter += 1

    start_index = len(vulnerability) - counter
    return vulnerability[start_index:]


def vulnerabilities_analysis(
    vex,
    extension: Extentions,
    specification: str,
    vulnerabilities: dict,
    lacks_vulnerabilities: dict,
) -> None:

    if specification == "OpenVEX":
        if "statements" in vex.keys():
            vulnerabilities["OpenVEX"].append(len(vex["statements"]))
            if len(vex["statements"]) == 0:
                lacks_vulnerabilities["OpenVEX"] += 1
        else:
            lacks_vulnerabilities["OpenVEX"] += 1

    elif specification == "CSAF":
        if "vulnerabilities" in vex.keys():
            vulnerabilities["CSAF"].append(len(vex["vulnerabilities"]))
            if len(vex["vulnerabilities"]) == 0:
                lacks_vulnerabilities["CSAF"] += 1
        else:
            lacks_vulnerabilities["CSAF"] += 1

    elif specification == "CycloneDX":
        if extension == Extentions.JSON:
            if "vulnerabilities" in vex.keys():
                vulnerabilities["CycloneDX"].append(len(vex["vulnerabilities"]))
                if len(vex["vulnerabilities"]) == 0:
                    lacks_vulnerabilities["CycloneDX"] += 1
            else:
                lacks_vulnerabilities["CycloneDX"] += 1
        elif extension == Extentions.XML:
            namespace = etree.QName(vex.tag).namespace
            for vulns in vex.findall(etree.QName(namespace, "vulnerabilities")):
                vulnerabilities["CycloneDX"].append(len(vulns))
                if len(vulns) == 0:
                    lacks_vulnerabilities["CycloneDX"] += 1
                break

    elif specification == "SPDX" and "@graph" in vex.keys():
        vuln_count = 0
        for element in vex["@graph"]:
            if (
                element["type"] == "security_Vulnerability"
                or element["type"] == "Vulnerability"
            ):
                vuln_count += 1
        vulnerabilities["SPDX"].append(vuln_count)
        if vuln_count == 0:
            lacks_vulnerabilities["SPDX"] += 1


def status_analysis(
    vex, extention: Extentions, spesification: str, buckets: dict
) -> dict:
    """
    Extracts the status of the vulnerability and count the occurences

    Parameters
    vex - the Vex file
    extention - the extention of the vex file, this is so we can handle both json and xml
    spesification - the spesification of the current Vex file
    buckets - the datastructure we add the databases to

    Returns
    buckets
    """
    found_status = False
    if extention == Extentions.JSON:
        if spesification == "OpenVEX" and "statements" in vex.keys():
            for statement in vex["statements"]:
                if type(statement) != dict:
                    continue
                if "status" in statement.keys():
                    match (statement["status"]):
                        case "not_affected":
                            buckets[spesification][Status.NOT_AFFECTED.label] += 1
                            found_status = True
                            break
                        case "affected":
                            buckets[spesification][Status.AFFECTED.label] += 1
                            found_status = True
                            break
                        case "fixed":
                            buckets[spesification][Status.FIXED.label] += 1
                            found_status = True
                            break
                        case "under_investigation":
                            buckets[spesification][
                                Status.UNDER_INVESTIGATION.label
                            ] += 1
                            found_status = True
                            break
                        case _:
                            buckets[spesification][Status.UNKNOWN.label] += 1
                            found_status = True
                            break

        elif spesification == "CSAF" and "vulnerabilities" in vex.keys():
            for vulnerability in vex["vulnerabilities"]:
                if "product_status" in vulnerability.keys():
                    final_products_properties = defaultdict()
                    for property, products in vulnerability["product_status"].items():
                        for product in products:
                            if product not in final_products_properties.keys():
                                final_products_properties[product] = Status.UNKNOWN
                            match property:
                                case "first_affected":
                                    if (
                                        final_products_properties[product]
                                        < Status.AFFECTED
                                    ):
                                        final_products_properties[product] = (
                                            Status.AFFECTED
                                        )
                                    break
                                case "first_fixed":
                                    if (
                                        final_products_properties[product]
                                        < Status.FIXED
                                    ):
                                        final_products_properties[product] = (
                                            Status.FIXED
                                        )
                                    break
                                case "fixed":
                                    if (
                                        final_products_properties[product]
                                        < Status.FIXED
                                    ):
                                        final_products_properties[product] = (
                                            Status.FIXED
                                        )
                                    break
                                case "known_affected":
                                    if (
                                        final_products_properties[product]
                                        < Status.AFFECTED
                                    ):
                                        final_products_properties[product] = (
                                            Status.AFFECTED
                                        )
                                    break
                                case "known_not_affected":
                                    if (
                                        final_products_properties[product]
                                        < Status.NOT_AFFECTED
                                    ):
                                        final_products_properties[product] = (
                                            Status.NOT_AFFECTED
                                        )
                                    break
                                case "last_affected":
                                    if (
                                        final_products_properties[product]
                                        < Status.AFFECTED
                                    ):
                                        final_products_properties[product] = (
                                            Status.AFFECTED
                                        )
                                    break
                                case "recommended":
                                    if (
                                        final_products_properties[product]
                                        < Status.FIXED
                                    ):
                                        final_products_properties[product] = (
                                            Status.FIXED
                                        )
                                    break
                                case "under_investigation":
                                    if (
                                        final_products_properties[product]
                                        < Status.UNDER_INVESTIGATION
                                    ):
                                        final_products_properties[product] = (
                                            Status.UNDER_INVESTIGATION
                                        )
                                    break
                        for product, affects in final_products_properties.items():
                            found_status = True
                            buckets[spesification][affects.label] += 1

        elif spesification == "CycloneDX" and "vulnerabilities" in vex.keys():
            for vulnerability in vex["vulnerabilities"]:
                if (
                    type(vulnerability) == dict
                    and "id" in vulnerability.keys()
                    and "affects" in vulnerability.keys()
                ):
                    for affected in vulnerability["affects"]:
                        found_status = True
                        if "versions" in affected.keys():
                            for version in affected["versions"]:
                                if type(version) == dict and "status" in version.keys():
                                    match version["status"]:
                                        case "affected":
                                            buckets[spesification][
                                                Status.AFFECTED.label
                                            ] += 1
                                        case "unaffected":
                                            buckets[spesification][
                                                Status.NOT_AFFECTED.label
                                            ] += 1
                                        case "unknown":
                                            buckets[spesification][
                                                Status.UNKNOWN.label
                                            ] += 1
                        else:
                            buckets[spesification][Status.UNKNOWN.label] += 1

        elif spesification == "SPDX" and "@graph" in vex.keys():
            relationships = [
                "VexAffectedVulnAssessmentRelationship",
                "VexFixedVulnAssessmentRelationship",
                "VexNotAffectedVulnAssessmentRelationship",
                "VexUnderInvestigationVulnAssessmentRelationship",
            ]
            for entry in vex["@graph"]:
                if (
                    entry["type"] == "Relationship"
                    and entry["relationshipType"] in relationships
                ):
                    found_status = True
                    match entry["relationshipType"]:
                        case "VexAffectedVulnAssessmentRelationship":
                            buckets[spesification][Status.AFFECTED.label] += 1
                            break
                        case "VexFixedVulnAssessmentRelationship":
                            buckets[spesification][Status.FIXED.label] += 1
                            break
                        case "VexNotAffectedVulnAssessmentRelationship":
                            buckets[spesification][Status.NOT_AFFECTED.label] += 1
                            break
                        case "VexUnderInvestigationVulnAssessmentRelationship":
                            buckets[spesification][Status.NOT_AFFECTED.label] += 1
                            break

    elif extention == Extentions.XML:
        if spesification == "CycloneDX":
            namespaces_keys = list(vex.nsmap.keys())
            for key in namespaces_keys:
                for vulnerabilities in vex.findall(
                    f"{f"{key}:" if key else ""}vulnerabilities", namespaces=vex.nsmap
                ):
                    for vulnerability in vulnerabilities.findall(
                        f"{f"{key}:" if key else ""}vulnerability", namespaces=vex.nsmap
                    ):
                        for affects in vulnerability.findall(
                            f"{f"{key}:" if key else ""}affects", namespaces=vex.nsmap
                        ):
                            for target in affects.findall(
                                f"{f"{key}:" if key else ""}target",
                                namespaces=vex.nsmap,
                            ):
                                for versions in target.findall(
                                    f"{f"{key}:" if key else ""}versions",
                                    namespaces=vex.nsmap,
                                ):
                                    for version in versions.findall(
                                        f"{f"{key}:" if key else ""}version",
                                        namespaces=vex.nsmap,
                                    ):
                                        for status in version.findall(
                                            f"{f"{key}:" if key else ""}status",
                                            namespaces=vex.nsmap,
                                        ):
                                            found_status = True
                                            match status.text:
                                                case "affected":
                                                    buckets[spesification][
                                                        Status.AFFECTED.label
                                                    ] += 1
                                                case "unaffected":
                                                    buckets[spesification][
                                                        Status.NOT_AFFECTED.label
                                                    ] += 1
                                                case "unknown":
                                                    buckets[spesification][
                                                        Status.UNKNOWN.label
                                                    ] += 1

    if found_status:
        buckets[spesification]["count"] += 1
    return buckets

def ratings_analysis(
    vex, extention: Extentions, spesification: str, buckets: dict
) -> dict:
    """
    Extracts the severity of vulnerabilities

    Parameters
    vex - the Vex file
    extention - the extention of the vex file, this is so we can handle both json and xml
    spesification - the spesification of the current Vex file
    buckets - the datastructure we add the databases to

    Returns
    buckets
    """
    found_rating = False
    if extention == Extentions.JSON:
        if spesification == "CSAF" and "vulnerabilities" in vex.keys():
            for vulnerability in vex["vulnerabilities"]:
                if "scores" in vulnerability.keys():
                    for item in vulnerability["scores"]:
                        for system in item.keys():
                            match system:
                                case "cvss_v2":
                                    if item[system]["baseScore"]:
                                        found_rating = True
                                        buckets[spesification]["CVSS"]["2"] += 1
                                        score = float(item[system]["baseScore"])
                                        buckets[spesification]["ratings"].append(score)
                                    break
                                case "cvss_v3":
                                    if item[system]["baseScore"]:
                                        found_rating = True
                                        buckets[spesification]["CVSS"]["3"] += 1
                                        score = float(item[system]["baseScore"])
                                        buckets[spesification]["ratings"].append(score)
                                    break
                                case _:
                                    break

        elif spesification == "CycloneDX" and "vulnerabilities" in vex.keys():
            for vulnerability in vex["vulnerabilities"]:
                if (
                    type(vulnerability) == dict
                    and "ratings" in vulnerability.keys()
                ):
                    for item in vulnerability["ratings"]:
                        if "method" in item.keys():
                            match item["method"]:
                                case "CVSSv2":
                                    if "score" in item.keys():
                                        score = item["score"]
                                        found_rating = True
                                        buckets[spesification]["CVSS"]["2"] += 1
                                        buckets[spesification]["ratings"].append(score)
                                    break
                                case "CVSSv3" | "CVSSv31":
                                    if "score" in item.keys():
                                        score = item["score"]
                                        found_rating = True
                                        buckets[spesification]["CVSS"]["3"] += 1
                                        buckets[spesification]["ratings"].append(score)
                                    break
                                case "other":
                                    if ("score" in item.keys()
                                        and "source" in item.keys()):
                                        found_rating = True
                                        score = item["score"]
                                        name = item["source"]["name"]
                                        buckets[spesification]["other"].append({"score": score, "name": name})
                                        buckets[spesification]["ratings"].append(score)
                                    break
                                # While supported none were found in the dataset
                                # so the code has been left incomplete
                                case "CVSSv4":
                                    if "score" in item.keys():
                                        score = item["score"]
                                        found_rating = True
                                        buckets[spesification]["CVSS"]["4"] += 1
                                        buckets[spesification]["ratings"].append(score)
                                case "OWASP":
                                    break

        elif spesification == "SPDX" and "@graph" in vex.keys():
            relationships = [
                "CvssV2VulnAssessmentRelationship",
                "CvssV3VulnAssessmentRelationship",
                "CvssV4VulnAssessmentRelationship",
                "EpssVulnAssessmentRelationship",
                "SsvcVulnAssessmentRelationship",
            ]
            for entry in vex["@graph"]:
                if (
                    entry["type"] == "Relationship"
                    and entry["relationshipType"] in relationships
                    and "security_score" in entry
                ):
                    found_rating = True
                    match entry["relationshipType"]:
                        case "CvssV2VulnAssessmentRelationship":
                            buckets[spesification]["CVSS"]["2"] += 1
                            buckets[spesification]["ratings"].append(float(entry["security_score"]))
                            break
                        case "CvssV3VulnAssessmentRelationship":
                            buckets[spesification]["CVSS"]["3"] += 1
                            buckets[spesification]["ratings"].append(float(entry["security_score"]))
                            break
                        case "CvssV4VulnAssessmentRelationship":
                            buckets[spesification]["CVSS"]["4"] += 1
                            buckets[spesification]["ratings"].append(float(entry["security_score"]))
                            break

    elif extention == Extentions.XML:
        if spesification == "CycloneDX":
            namespaces_keys = list(vex.nsmap.keys())
            for key in namespaces_keys:
                for vulnerabilities in vex.findall(
                    f"{f"{key}:" if key else ""}vulnerabilities", namespaces=vex.nsmap
                ):
                    for vulnerability in vulnerabilities.findall(
                        f"{f"{key}:" if key else ""}vulnerability", namespaces=vex.nsmap
                    ):
                        for ratings in vulnerability.findall(
                            f"{f"{key}:" if key else ""}ratings", namespaces=vex.nsmap
                        ):
                            for rating in ratings.findall(
                                f"{f"{key}:" if key else ""}rating",
                                namespaces=vex.nsmap,
                            ):
                                score_str = rating.find(f"{f"{key}:" if key else ""}score", namespaces=vex.nsmap)
                                method = rating.find(f"{f"{key}:" if key else ""}method", namespaces=vex.nsmap)

                                try:
                                    score = float(score_str.text)
                                except Exception as err:
                                    continue
                                if method is not None:
                                    match method.text:
                                        case "CVSSv2":
                                            found_rating = True
                                            buckets[spesification]["CVSS"]["2"] += 1
                                            buckets[spesification]["ratings"].append(score)
                                            break
                                        case "CVSSv3" | "CVSSv31":
                                            found_rating = True
                                            buckets[spesification]["CVSS"]["3"] += 1
                                            buckets[spesification]["ratings"].append(score)
                                            break
                                        case "other":
                                            source = rating.find(f"{f"{key}:" if key else ""}source", namespaces=vex.nsmap)
                                            if source is None:
                                                continue
                                            name_element = source.find(f"{f"{key}:" if key else ""}name", namespaces=vex.nsmap)
                                            if name_element is None:
                                                continue
                                            found_rating = True
                                            name = source.find(f"{f"{key}:" if key else ""}name", namespaces=vex.nsmap).text
                                            buckets[spesification]["other"].append({"score": score, "name": name})
                                            buckets[spesification]["ratings"].append(score)
                                            break
                                        case "CVSSv4":
                                            found_rating = True
                                            buckets[spesification]["CVSS"]["4"] += 1
                                            buckets[spesification]["ratings"].append(score)
                                            break
                                        # While supported none were found in the dataset
                                        # so the code has been left incomplete
                                        case "OWASP":
                                            break
    if found_rating:
        buckets[spesification]["count"] += 1
    return buckets


def repository_analysis(document, specification: str, buckets: dict) -> dict:
    """
    Extracts the repository the file comes from

    Parameters
    document - the mongodb document
    spesification - the spesification of the current document file
    buckets - the datastructure we add the repository data to

    Returns
    buckets
    """
    commit_url = document["commit_url"]
    repo = commit_url.split("repos/")
    repo = repo[1].split("/", 2)[0] + "/" + repo[1].split("/", 2)[1]
    buckets[specification][repo] += 1
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
            "CVSS": {
                "2": 0,
                "3": 0,
                "4": 0
            },
            "OWASP": 0,
            "other": [],
            "ratings": [],
            "count" : 0
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
        if args.vulnerabilities or args.all:
            vulnerabilities_analysis(
                vex=vex,
                extension=extention,
                specification=spesification,
                vulnerabilities=vulnerabilities,
                lacks_vulnerabilities=lacks_vulnerabilities,
            )

        if args.databases or args.all:
            databases = database_analysis(
                vex=vex,
                extention=extention,
                spesification=spesification,
                buckets=databases,
            )
        if args.status or args.all:
            status_analysis(
                vex=vex,
                extention=extention,
                spesification=spesification,
                buckets=statuses,
            )

        if args.rating or args.all:
            ratings_analysis(
                vex=vex,
                extention=extention,
                spesification=spesification,
                buckets=ratings
            )

        if args.repo or args.all:
            repository_analysis(
                document=document,
                specification=spesification,
                buckets=repos
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
    pass


if __name__ == "__main__":
    main()
