import pandas as pd
from pathlib import Path

def files_table(file_counts: dict, repos: dict, total_documents: int, folder: Path) -> None:
    file_names = []
    content = []

    # files = pd.DataFrame(file_counts)
    files = []
    repo_count = 0
    for specification in file_counts:
        if specification == "name":
            continue
        repo = len(repos[specification].keys()) - 1
        # The "count" row in repos is not a repository
        repo_count += repo
        files.append({
            "specification": specification,
            "count": file_counts[specification],
            "percentage": file_counts[specification] / total_documents,
            "repositories": repo,
        })
    files = sorted(files, key=lambda d: d["count"], reverse=True)
    files.append({
        "specification": "Total",
        "count": total_documents,
        "percentage": total_documents / total_documents,
        "repositories": repo_count,
    })
    files_df = pd.DataFrame(files)
    files_df.set_index("specification", inplace=True)
    styler = files_df.style.format(
        precision=2, decimal=",", thousands=" ", escape="latex"
    )
    file_names.append("files.tex")
    content.append(
        styler.to_latex(
            environment="longtable",
            column_format="lrrr",
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