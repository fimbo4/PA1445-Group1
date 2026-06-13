from collections import defaultdict
from enum import Enum
from pathlib import Path

import pandas as pd
from lxml import etree

from analysis.extentions import Extentions
from analysis.Status import Status

import jsonc
import json
from copy import deepcopy

errors = []


def has_status(
    vex, extention: Extentions, specification: str, buckets: dict
) -> bool:
    """
    A repurposed function to be used for checking if a status is present in the commit gathering
    """
    found_status = False
    if extention == Extentions.JSON:
        if specification == "OpenVEX" and "statements" in vex.keys():
            for statement in vex["statements"]:
                if type(statement) != dict:
                    continue
                if "status" in statement.keys():
                    match (statement["status"]):
                        case "not_affected":
                            return True
                            found_status = True
                            break
                        case "affected":
                            return True
                            found_status = True
                            break
                        case "fixed":
                            return True
                            found_status = True
                            break
                        case "under_investigation":
                            return True
                            found_status = True
                            break
                        case _:
                            return True
                            found_status = True
                            break

        elif specification == "CSAF" and "vulnerabilities" in vex.keys():
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
                            return True
                            found_status = True
                            buckets[specification][affects.label] += 1

        elif specification == "CycloneDX" and "vulnerabilities" in vex.keys():
            for vulnerability in vex["vulnerabilities"]:
                if (
                    type(vulnerability) == dict
                    and "id" in vulnerability.keys()
                    and "affects" in vulnerability.keys()
                ):
                    for affected in vulnerability["affects"]:
                        return True
                        found_status = True
                        if "versions" in affected.keys():
                            for version in affected["versions"]:
                                if type(version) == dict and "status" in version.keys():
                                    match version["status"]:
                                        case "affected":
                                            buckets[specification][
                                                Status.AFFECTED.label
                                            ] += 1
                                        case "unaffected":
                                            buckets[specification][
                                                Status.NOT_AFFECTED.label
                                            ] += 1
                                        case "unknown":
                                            buckets[specification][
                                                Status.UNKNOWN.label
                                            ] += 1
                        else:
                            buckets[specification][Status.UNKNOWN.label] += 1

        elif specification == "SPDX" and "@graph" in vex.keys():
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
                    return True
                    found_status = True
                    match entry["relationshipType"]:
                        case "VexAffectedVulnAssessmentRelationship":
                            buckets[specification][Status.AFFECTED.label] += 1
                            break
                        case "VexFixedVulnAssessmentRelationship":
                            buckets[specification][Status.FIXED.label] += 1
                            break
                        case "VexNotAffectedVulnAssessmentRelationship":
                            buckets[specification][Status.NOT_AFFECTED.label] += 1
                            break
                        case "VexUnderInvestigationVulnAssessmentRelationship":
                            buckets[specification][Status.NOT_AFFECTED.label] += 1
                            break

    elif extention == Extentions.XML:
        if specification == "CycloneDX":
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
                                            return True
                                            found_status = True
                                            match status.text:
                                                case "affected":
                                                    buckets[specification][
                                                        Status.AFFECTED.label
                                                    ] += 1
                                                case "unaffected":
                                                    buckets[specification][
                                                        Status.NOT_AFFECTED.label
                                                    ] += 1
                                                case "unknown":
                                                    buckets[specification][
                                                        Status.UNKNOWN.label
                                                    ] += 1

    return found_status


def has_vulnerabilities(
    vex,
    extension: Extentions,
    specification: str,
    vulnerabilities: list,
    lacks_vulnerabilities: dict,
) -> bool:
    """
    A repurposed function to be used for checking if a vulnerability is present in the commit gathering
    """
    if specification == "OpenVEX":
        if "statements" in vex.keys():
            return len(vex["statements"]) > 0
            vulnerabilities.append(
                {
                    "length": len(vex["statements"]),
                    "specification": specification,
                }
            )
            if len(vex["statements"]) == 0:
                lacks_vulnerabilities["OpenVEX"] += 1
        else:
            return False

    elif specification == "CSAF":
        if "vulnerabilities" in vex.keys():
            return len(vex["vulnerabilities"]) > 0
            vulnerabilities.append(
                {
                    "length": len(vex["vulnerabilities"]),
                    "specification": specification,
                }
            )
            if len(vex["vulnerabilities"]) == 0:
                lacks_vulnerabilities["CSAF"] += 1
        else:
            return False

    elif specification == "CycloneDX":
        if extension == Extentions.JSON:
            if "vulnerabilities" in vex.keys():
                return len(vex["vulnerabilities"]) > 0
                vulnerabilities.append(
                    {
                        "length": len(vex["vulnerabilities"]),
                        "specification": specification,
                    }
                )
                if len(vex["vulnerabilities"]) == 0:
                    lacks_vulnerabilities["CycloneDX"] += 1
            else:
                return False
        elif extension == Extentions.XML:
            namespace = etree.QName(vex.tag).namespace
            for vulns in vex.findall(etree.QName(namespace, "vulnerabilities")):
                return len(vulns) > 0
                vulnerabilities.append(
                    {
                        "length": (len(vulns)),
                        "specification": specification,
                    }
                )
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
        vulnerabilities.append(
            {
                "length": vuln_count,
                "specification": specification,
            }
        )
        return vuln_count > 0
    

def verify_vex(document, specification):
    empty_dict = defaultdict(int)
    statuses = {
        "OpenVEX": deepcopy(empty_dict),
        "CSAF": deepcopy(empty_dict),
        "CycloneDX": deepcopy(empty_dict),
        "SPDX": deepcopy(empty_dict),
    }
    if document["extension"] == "json" or document["extension"] == "jsonld":
        try:
            vex = jsonc.loads(
                document["file"])
            extention = Extentions.JSON
        except:
            return False
    elif document["extension"] == "xml":
        try:
            vex = etree.fromstring(document["file"].encode("utf-8"))
            extention = Extentions.XML
        except:
            return False
    else:
        return False
    if extention == Extentions.JSON and type(vex) == list: #??? stupid
        for v in vex:
            if has_status(v, extention, specification, statuses) and has_vulnerabilities(v, extention, specification, [], {}):
                return True
    else:
        if has_status(vex, extention, specification, statuses) and has_vulnerabilities(vex, extention, specification, [], {}):
            return True
    return False