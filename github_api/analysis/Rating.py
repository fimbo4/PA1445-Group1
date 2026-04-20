from lxml import etree

from .extentions import Extentions


def ratings_analysis(
    vex, extention: Extentions, specification: str, buckets: dict
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
                    for item in vulnerability["scores"]:
                        for system in item.keys():
                            match system:
                                case "cvss_v2":
                                    if item[system]["baseScore"]:
                                        found_rating = True
                                        buckets[specification]["CVSS"]["2"] += 1
                                        score = float(item[system]["baseScore"])
                                        buckets[specification]["ratings"].append(score)
                                    break
                                case "cvss_v3":
                                    if item[system]["baseScore"]:
                                        found_rating = True
                                        buckets[specification]["CVSS"]["3"] += 1
                                        score = float(item[system]["baseScore"])
                                        buckets[specification]["ratings"].append(score)
                                    break
                                case _:
                                    break

        elif specification == "CycloneDX" and "vulnerabilities" in vex.keys():
            for vulnerability in vex["vulnerabilities"]:
                if type(vulnerability) == dict and "ratings" in vulnerability.keys():
                    for item in vulnerability["ratings"]:
                        if "method" in item.keys():
                            match item["method"]:
                                case "CVSSv2":
                                    if "score" in item.keys():
                                        score = item["score"]
                                        found_rating = True
                                        buckets[specification]["CVSS"]["2"] += 1
                                        buckets[specification]["ratings"].append(score)
                                    break
                                case "CVSSv3" | "CVSSv31":
                                    if "score" in item.keys():
                                        score = item["score"]
                                        found_rating = True
                                        buckets[specification]["CVSS"]["3"] += 1
                                        buckets[specification]["ratings"].append(score)
                                    break
                                case "other":
                                    if (
                                        "score" in item.keys()
                                        and "source" in item.keys()
                                    ):
                                        found_rating = True
                                        score = item["score"]
                                        name = item["source"]["name"]
                                        buckets[specification]["other"].append(
                                            {"score": score, "name": name}
                                        )
                                        buckets[specification]["ratings"].append(score)
                                    break
                                # While supported none were found in the dataset
                                # so the code has been left incomplete
                                case "CVSSv4":
                                    if "score" in item.keys():
                                        score = item["score"]
                                        found_rating = True
                                        buckets[specification]["CVSS"]["4"] += 1
                                        buckets[specification]["ratings"].append(score)
                                case "OWASP":
                                    break

        elif specification == "SPDX" and "@graph" in vex.keys():
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
                            buckets[specification]["CVSS"]["2"] += 1
                            buckets[specification]["ratings"].append(
                                float(entry["security_score"])
                            )
                            break
                        case "CvssV3VulnAssessmentRelationship":
                            buckets[specification]["CVSS"]["3"] += 1
                            buckets[specification]["ratings"].append(
                                float(entry["security_score"])
                            )
                            break
                        case "CvssV4VulnAssessmentRelationship":
                            buckets[specification]["CVSS"]["4"] += 1
                            buckets[specification]["ratings"].append(
                                float(entry["security_score"])
                            )
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
                                    match method.text:
                                        case "CVSSv2":
                                            found_rating = True
                                            buckets[specification]["CVSS"]["2"] += 1
                                            buckets[specification]["ratings"].append(
                                                score
                                            )
                                            break
                                        case "CVSSv3" | "CVSSv31":
                                            found_rating = True
                                            buckets[specification]["CVSS"]["3"] += 1
                                            buckets[specification]["ratings"].append(
                                                score
                                            )
                                            break
                                        case "other":
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
                                            found_rating = True
                                            name = source.find(
                                                f"{f"{key}:" if key else ""}name",
                                                namespaces=vex.nsmap,
                                            ).text
                                            buckets[specification]["other"].append(
                                                {"score": score, "name": name}
                                            )
                                            buckets[specification]["ratings"].append(
                                                score
                                            )
                                            break
                                        case "CVSSv4":
                                            found_rating = True
                                            buckets[specification]["CVSS"]["4"] += 1
                                            buckets[specification]["ratings"].append(
                                                score
                                            )
                                            break
                                        # While supported none were found in the dataset
                                        # so the code has been left incomplete
                                        case "OWASP":
                                            break
    if found_rating:
        buckets[specification]["count"] += 1
    return buckets
