from lxml import etree

from .extentions import Extentions
from pathlib import Path
import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd

def ratings_analysis(
    vex, extention: Extentions, specification: str, table: list, counter: dict
) -> dict:
    """
    Extracts the severity of vulnerabilities

    Parameters
    vex - the Vex file
    extention - the extention of the vex file, this is so we can handle both json and xml
    specification - the specification of the current Vex file
    buckets - the datastructure we add the databases to

    Returns
    buckets
    """
    found_rating = False
    if extention == Extentions.JSON:
        if specification == "CSAF" and "vulnerabilities" in vex.keys():
            for vulnerability in vex["vulnerabilities"]:
                if "scores" in vulnerability.keys():
                    methods = [
                            "cvss_v2",
                            "cvss_v3",
                        ]
                    for item in vulnerability["scores"]:
                        for method in item.keys():
                            if (method in methods
                                and "baseScore" in item[method].keys()):
                                try: 
                                    score = float(item[method]["baseScore"])
                                except Exception as err:
                                    continue
                                found_rating = True
                                table.append({
                                    "score": score,
                                    "specification": specification,
                                    "method": method,
                                })

        elif specification == "CycloneDX" and "vulnerabilities" in vex.keys():
            for vulnerability in vex["vulnerabilities"]:
                if type(vulnerability) == dict and "ratings" in vulnerability.keys():
                    for item in vulnerability["ratings"]:
                        if "method" in item.keys():
                            if (item["method"] == "other"
                                and "source" in item.keys()):
                                method = item["source"]["name"]
                            else:
                                method = item["method"]
                            if "score" in item.keys():
                                score = item["score"]
                            else:
                                continue
                            if type(score) == str:
                                try:
                                    score = float(score)
                                except Exception as err:
                                    continue
                            found_rating = True
                            table.append({
                                    "score": score,
                                    "specification": specification,
                                    "method": method,
                            })

        elif specification == "SPDX" and "@graph" in vex.keys():
            relationships = [
                "CvssV2VulnAssessmentRelationship",
                "CvssV3VulnAssessmentRelationship",
                "CvssV4VulnAssessmentRelationship",
            ]
            for entry in vex["@graph"]:
                if (
                    entry["type"] == "Relationship"
                    and entry["relationshipType"] in relationships
                    and "security_score" in entry
                ):
                    try:
                        score = float(entry["security_score"])
                    except Exception as err:
                        continue
                    found_rating = True
                    table.append({
                        "score": score,
                        "specification": specification,
                        "method": entry["relationshipType"],
                    })

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
                        for ratings in vulnerability.findall(
                            f"{f"{key}:" if key else ""}ratings", namespaces=vex.nsmap
                        ):
                            for rating in ratings.findall(
                                f"{f"{key}:" if key else ""}rating",
                                namespaces=vex.nsmap,
                            ):
                                score_str = rating.find(
                                    f"{f"{key}:" if key else ""}score",
                                    namespaces=vex.nsmap,
                                )
                                method = rating.find(
                                    f"{f"{key}:" if key else ""}method",
                                    namespaces=vex.nsmap,
                                )

                                try:
                                    score = float(score_str.text)
                                except Exception as err:
                                    continue
                                if method is not None:
                                    if (method.text == "other"):
                                        source = rating.find(
                                            f"{f"{key}:" if key else ""}source",
                                            namespaces=vex.nsmap,
                                        )
                                        if source is None:
                                            continue
                                        name_element = source.find(
                                            f"{f"{key}:" if key else ""}name",
                                            namespaces=vex.nsmap,
                                        )
                                        if name_element is None:
                                            continue
                                        name = source.find(
                                            f"{f"{key}:" if key else ""}name",
                                            namespaces=vex.nsmap,
                                        ).text
                                    else:
                                        name = method.text
                                    if type(score) == str:
                                        try:
                                            score = float(score)
                                        except Exception as err:
                                            continue
                                    found_rating = True
                                    table.append({
                                            "score": score,
                                            "specification": specification,
                                            "method": name,
                                    })

    if found_rating:
        counter[specification] += 1
    return table
