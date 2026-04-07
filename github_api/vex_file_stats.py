#import pandas as pd
import json
from database import vexDB
from statistics import mean, median, mode
#from flatten_json import flatten

def openvex_analysis(db: vexDB):
    """
    mean mode median for openvex vulnerabilities
    """
    
    failed_to_read = 0
    num_files = 0
    filetypes = {}
    statements = []

    vex_files = db.retrieve_collection_data("OpenVEX")
    for file in vex_files:
        filetypes[file["extension"]] = filetypes.setdefault(file["extension"], 0) + 1
        num_files += 1
        try:
            vex_contents = json.loads(file["file"])  
        except:
            failed_to_read += 1
            continue
        statements.append(len(vex_contents["statements"]))
        #pandas_json = pd.DataFrame(pd.json_normalize(vex_contents))
        #flat_json = flatten(vex_contents)
    
    print("Median statements: ", median(statements))
    print("Mean statements: ", mean(statements))
    print("Mode statements: ", mode(statements))
    print("Failed to read: ", failed_to_read)
    print("Number of files: ", num_files)
    print(filetypes)

def cyclonedx_analysis(db: vexDB):
    failed_to_read = 0
    num_files = 0
    filetypes = {}

    vex_files = db.retrieve_collection_data("CycloneDX")
    for file in vex_files:
        filetypes[file["extension"]] = filetypes.setdefault(file["extension"], 0) + 1
        num_files += 1
        try:
            vex_contents = json.loads(file["file"])  #cdx needs to read xml too
        except:
            failed_to_read += 1
            continue
    print("Failed to read: ", failed_to_read)
    print("Number of files: ", num_files)
    print(filetypes)

def csaf_analysis(db: vexDB):
    failed_to_read = 0
    num_files = 0
    filetypes = {}

    vex_files = db.retrieve_collection_data("CSAF")
    for file in vex_files:
        filetypes[file["extension"]] = filetypes.setdefault(file["extension"], 0) + 1
        num_files += 1
        try:
            vex_contents = json.loads(file["file"])  
        except:
            failed_to_read += 1
            continue
    print("Failed to read: ", failed_to_read)
    print("Number of files: ", num_files)
    print(filetypes)

def spdx_analysis(db: vexDB):
    failed_to_read = 0
    num_files = 0
    filetypes = {}

    vex_files = db.retrieve_collection_data("SPDX")
    for file in vex_files:
        filetypes[file["extension"]] = filetypes.setdefault(file["extension"], 0) + 1
        num_files += 1
        try:
            vex_contents = json.loads(file["file"])  
        except:
            failed_to_read += 1
            continue
    print("Failed to read: ", failed_to_read)
    print("Number of files: ", num_files)
    print(filetypes)

def main():
    db = vexDB()
    openvex_analysis(db)
    csaf_analysis(db)
    spdx_analysis(db)
    cyclonedx_analysis(db)

if __name__ == "__main__":
    main()