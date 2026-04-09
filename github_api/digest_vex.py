from database import vexDB
from tqdm import tqdm

# 2 transform into pythonic data structure (in db file?)
# 3 gather vex spesific datapoints
# 3.a Average vulnerabilities per file
# 3.b Which Tools are used if any
# 3.c Spesification version
# 3.d databases
# 3.e Vulnerability status
# 3.f Vulnerability severity (Buckets?)
# 4 Make plots

def main() -> None:
    database = vexDB()
    document_count = database.count_documents()
    for document in tqdm(database.get_all_documents(), desc="Analyzing document", total=document_count, unit="documents"):
        pass


if __name__ == "__main__":
    main()