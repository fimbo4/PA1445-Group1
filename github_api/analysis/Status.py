from collections import defaultdict
from enum import Enum
from pathlib import Path

import pandas as pd
from lxml import etree

from .extentions import Extentions

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


def status_analysis(
    vex, extention: Extentions, specification: str, buckets: dict
) -> dict:
    """
    Extracts the status of the vulnerability and count the occurences

    Parameters
    vex - the Vex file
    extention - the extention of the vex file, this is so we can handle both json and xml
    specification - the specification of the current Vex file
    buckets - the datastructure we add the databases to

    Returns
    buckets
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
                            buckets[specification][Status.NOT_AFFECTED.label] += 1
                            found_status = True
                            break
                        case "affected":
                            buckets[specification][Status.AFFECTED.label] += 1
                            found_status = True
                            break
                        case "fixed":
                            buckets[specification][Status.FIXED.label] += 1
                            found_status = True
                            break
                        case "under_investigation":
                            buckets[specification][
                                Status.UNDER_INVESTIGATION.label
                            ] += 1
                            found_status = True
                            break
                        case _:
                            buckets[specification][Status.UNKNOWN.label] += 1
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

    if found_status:
        buckets[specification]["count"] += 1
    return buckets


def status_tables(buckets: dict, file_count: dict, folder: Path) -> None:
    file_names = []
    content = []

    # Percentage of statuses
    status_count = {}
    for specification in buckets:
        status_count[specification] = {
            "count": buckets[specification]["count"],
            "percentage": buckets[specification]["count"] / file_count[specification],
        }
    status_count_df = pd.DataFrame(data=status_count)
    status_count_df = status_count_df.transpose()
    styler = status_count_df.style.format(
        precision=2, decimal=",", thousands=" ", escape="latex"
    )
    file_names.append("count_status.tex")
    content.append(
        styler.to_latex(
            environment="longtable",
            column_format="p{10cm}r",
            label="tab:Status proportion",
            caption="Table detailing the proportion of files where a status was found",
            hrules=True,
        )
    )

    statuses = pd.DataFrame(buckets)
    statuses.drop(labels=["count"], axis="index", inplace=True)
    statuses.fillna(value=0, inplace=True)
    styler = statuses.style.format(
        precision=2, decimal=",", thousands=" ", escape="latex"
    )
    file_names.append("statuses.tex")
    content.append(
        styler.to_latex(
            environment="longtable",
            column_format="lrrrr",
            label="tab:Statuses",
            caption="Table showing how many of each status was found per specification",
            hrules=True,
        )
    )

    for file_name, content in zip(file_names, content):
        filepath = folder / file_name
        if not filepath.exists():
            filepath.touch()
        with filepath.open("w", encoding="utf-8") as file:
            file.write(content)
