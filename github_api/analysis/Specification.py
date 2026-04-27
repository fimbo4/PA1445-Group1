from pathlib import Path

import pandas as pd
from lxml import etree

from .extentions import Extentions


def specification_analysis(
    vex, extention: Extentions, specification: str, buckets: dict
) -> dict:
    """
    Extracts the version number of the specification

    Parameters
    vex - the Vex file
    extention - the extention of the vex file, this is so we can handle both json and xml
    specification - the specification of the current Vex file
    buckets - the datastructure we add another version number to

    Returns
    buckets
    """
    found_specification = False
    if extention == Extentions.JSON:
        if specification == "OpenVEX" and "@context" in vex.keys():
            context = vex["@context"]
            version = context.replace("https://openvex.dev/ns/v", "")
            buckets[specification][version] += 1
            found_specification = True

        elif specification == "CSAF" and "document" in vex.keys():
            buckets[specification][vex["document"]["csaf_version"]] += 1
            found_specification = True

        elif specification == "CycloneDX" and "specVersion" in vex.keys():

            buckets[specification][vex["specVersion"]] += 1
            found_specification = True

        elif specification == "SPDX" and "@graph" in vex.keys():
            for entry in vex["@graph"]:
                if entry["type"] == "CreationInfo" and "specVersion" in entry.keys():
                    buckets[specification][entry["specVersion"]] += 1
                    found_specification = True

    elif extention == Extentions.XML:
        if specification == "CycloneDX":
            namespace = etree.QName(vex.tag).namespace
            version = namespace.replace("http://cyclonedx.org/schema/bom/", "")
            buckets[specification][version] += 1
            found_specification = True

    if found_specification:
        buckets[specification]["count"] += 1
    return buckets


def specification_tables(buckets: dict, file_count: dict, folder: Path) -> None:
    file_names = []
    content = []

    # Percentage of tools
    specification_count = {}
    for specification in buckets:
        specification_count[specification] = {
            "count": buckets[specification]["count"],
            "percentage": buckets[specification]["count"] / file_count[specification],
        }
    specification_count_df = pd.DataFrame(data=specification_count)
    specification_count_df = specification_count_df.transpose()
    styler = specification_count_df.style.format(
        precision=2, decimal=",", thousands=" ", escape="latex"
    )
    file_names.append("count_specification.tex")
    content.append(
        styler.to_latex(
            position_float="centering",
            label="Tools proportion",
            caption="Table detailing the proportion of files generated with a tool",
            hrules=True,
        )
    )

    specifications = pd.DataFrame(buckets)
    specifications.fillna(value=0, inplace=True)
    styler = specifications.style.format(
        precision=2, decimal=",", thousands=" ", escape="latex"
    )
    file_names.append("specifications.tex")
    content.append(
        styler.to_latex(
            environment="longtable",
            column_format="p{10cm}r",
            label="SPDX_tools",
            caption="Table showing the different versions that were found for the specifications",
            hrules=True,
        )
    )

    for file_name, content in zip(file_names, content):
        filepath = folder / file_name
        if not filepath.exists():
            filepath.touch()
        with filepath.open("w", encoding="utf-8") as file:
            file.write(content)
