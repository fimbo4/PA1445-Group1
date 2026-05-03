import pandas as pd
from pathlib import Path

def files_table(file_counts: dict, total_documents: int, folder: Path) -> None:
    file_names = []
    content = []

    # files = pd.DataFrame(file_counts)
    files = []
    for specification in file_counts:
        if specification == "name":
            continue
        files.append({
            "specification": specification,
            "count": file_counts[specification],
            "percentage": file_counts[specification] / total_documents,
        })
    files.append({
        "specification": "Total",
        "count": total_documents,
        "percentage": total_documents / total_documents,
    })
    files_df = pd.DataFrame(files)
    files_df.reset_index(drop=True, inplace=True)
    styler = files_df.style.format(
        precision=2, decimal=",", thousands=" ", escape="latex"
    )
    file_names.append("files.tex")
    content.append(
        styler.to_latex(
            environment="longtable",
            column_format="p{10cm}r",
            label="tab:Files distribution",
            caption="Table detailing the proportion of files over the different specifications",
            hrules=True,
        )
    )
    
    for file_name, content in zip(file_names, content):
        filepath = folder / file_name
        if not filepath.exists():
            filepath.touch()
        with filepath.open("w", encoding="utf-8") as file:
            file.write(content)