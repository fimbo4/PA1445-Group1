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

def 