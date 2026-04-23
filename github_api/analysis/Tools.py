from pathlib import Path

import pandas as pd
import seaborn as sns
from lxml import etree

from .extentions import Extentions


def tools_analysis(
    vex, extention: Extentions, specification: str, buckets: dict
) -> dict:
    """
    Extracts the name of the tools used to generate the vex

    Parameters
    vex - the Vex file
    extention - the extention of the vex file, this is so we can handle both json and xml
    specification - the specification of the current Vex file
    buckets - the datastructure we add another tool to

    Returns
    buckets
    """
    found_tool = False
    if extention == Extentions.JSON:
        if specification == "OpenVEX" and "tooling" in vex.keys():
            buckets[specification][vex["tooling"]] += 1
            found_tool = True

        elif specification == "CSAF" and "document" in vex.keys():
            # CSAF dosen't have a "tools" field, but a tool could be a publisher.
            buckets[specification][vex["document"]["publisher"]["name"]] += 1
            found_tool = True

        elif (
            specification == "CycloneDX"
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
                buckets[specification][tool["name"]] += 1
                found_tool = True

        elif specification == "SPDX" and "@graph" in vex.keys():
            for entry in vex["@graph"]:
                if entry["type"] == "CreationInfo" and "createdUsing" in entry.keys():
                    for tool in entry["createdUsing"]:
                        buckets[specification][tool] += 1
                        found_tool = True

    elif extention == Extentions.XML:
        if specification == "CycloneDX":
            namespace = etree.QName(vex.tag).namespace
            for metadata in vex.findall(etree.QName(namespace, "metadata")):
                for tools in metadata.findall(etree.QName(namespace, "tools")):
                    for tool in tools:
                        for sub_element in tool:
                            if etree.QName(sub_element.tag).localname == "name":
                                buckets[specification][sub_element.text] += 1
                                found_tool = True
    if found_tool:
        buckets[specification]["count"] += 1
    return buckets


def tools_tables(buckets: dict, file_count: dict, folder: Path) -> None:
    file_names = ["count_tools.tex"]
    contense = []

    # Percentage of tools
    tools_vs_non_tools = {}
    for specification in buckets:
        tools_vs_non_tools[specification] = {
            "count": buckets[specification]["count"],
            "percentage": buckets[specification]["count"] / file_count[specification],
        }
    tools_vs_non_tools_df = pd.DataFrame(data=tools_vs_non_tools)
    tools_vs_non_tools_df = tools_vs_non_tools_df.transpose()
    styler = tools_vs_non_tools_df.style.format(precision=2, decimal=",", thousands=" ", escape="latex")
    # styler = pd.io.formats.style.Styler(data=tools_vs_non_tools_df, precision=2, decimal=",", thousands=" ", escape="latex")
    contense.append(styler.to_latex(position_float="centering", label="Tools proportion", caption="Table detailing the proportion of files generated with a tool", hrules=True))
    # https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.io.formats.style.Styler.to_latex.html#pandas.io.formats.style.Styler.to_latex instead?

    # Map buckets
    tools = pd.DataFrame(buckets)
    CycloneDX_tools = tools.dropna(subset=["CycloneDX"])
    # CycloneDX_tools.drop(["SPDX", "OpenVEX", "CSAF"], inplace=True)
    styler = CycloneDX_tools.style.format(precision=2, decimal=",", thousands=" ", escape="latex")
    file_names.append("Tools_in_use.tex")
    contense.append(styler.to_latex(environment="longtable", label="Tools", caption="Table naming all the tools used", hrules=True))

    for file_name, content in zip(file_names, contense):
        filepath = folder / file_name
        if not filepath.exists():
            filepath.touch()
        with filepath.open("w", encoding="utf-8") as file:
            file.write(content)
