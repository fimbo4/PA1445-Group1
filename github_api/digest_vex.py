from database import vexDB
from tqdm import tqdm
import jsonc # Helps with parsing illegal Json
from enum import Enum
import xml.etree.ElementTree as ET

class Extentions(Enum):
    JSON = 1
    XML = 2

# 3 gather vex spesific datapoints
# 3.a Average vulnerabilities per file
# 3.b Which Tools are used if any
# 3.c Spesification version (On a per spesification basis)
# 3.d databases
# 3.e Vulnerability status
# 3.f Vulnerability severity (Buckets?)
# 4 Make plots

def main() -> None:
    database = vexDB()
    document_count = database.count_documents()
    for document, spesification in tqdm(database.get_all_documents(), desc="Analyzing document", total=document_count, unit="documents"):
        match (document["extension"]):
            case "json" | "jsonld":
                # Cast file to dict
                vex = jsonc.loads(document["file"], )
                # Set extention variable (enum for readability?)
                extention = Extentions.JSON
            case "xml":
                # Cast file to xml tree
                vex = ET.fromstring(document["file"])
                # Set extention variable (enum for readability?)
                extention = Extentions.XML
            case _:
                print("Unknown extention. Skipping")
        


if __name__ == "__main__":
    main()