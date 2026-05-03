from pathlib import Path

import pandas as pd


def repository_analysis(document, specification: str, buckets: dict) -> dict:
    """
    Extracts the repository the file comes from

    Parameters
    document - the mongodb document
    specification - the specification of the current document file
    buckets - the datastructure we add the repository data to

    Returns
    buckets
    """
    commit_url = document["commit_url"]
    repo = commit_url.split("repos/")
    repo = repo[1].split("/", 2)[0] + "/" + repo[1].split("/", 2)[1]
    buckets[specification][repo] += 1
    return buckets


def repository_tables(buckets: dict, folder: Path) -> None:
    file_names = []
    content = []

    repos = pd.DataFrame(buckets)
    CSAF_repos = repos.dropna(subset=["CSAF"])
    CSAF_repos.drop(columns=["SPDX", "OpenVEX", "CycloneDX"], inplace=True)
    styler = CSAF_repos.style.format(
        precision=2, decimal=",", thousands=" ", escape="latex"
    )
    file_names.append("CSAF_repos.tex")
    content.append(
        styler.to_latex(
            environment="longtable",
            column_format="p{10cm}r",
            label="tab:CSAF repos",
            caption="Table naming repositories with CSAF files",
            hrules=True,
        )
    )

    CycloneDX_repos = repos.dropna(subset=["CycloneDX"])
    CycloneDX_repos.drop(columns=["SPDX", "OpenVEX", "CSAF"], inplace=True)
    styler = CycloneDX_repos.style.format(
        precision=2, decimal=",", thousands=" ", escape="latex"
    )
    file_names.append("CycloneDX_repos.tex")
    content.append(
        styler.to_latex(
            environment="longtable",
            column_format="p{10cm}r",
            label="tab:CycloneDX repos",
            caption="Table naming repositories with CycloneDX files",
            hrules=True,
        )
    )

    OpenVEX_repos = repos.dropna(subset=["OpenVEX"])
    OpenVEX_repos.drop(columns=["SPDX", "CycloneDX", "CSAF"], inplace=True)
    styler = OpenVEX_repos.style.format(
        precision=2, decimal=",", thousands=" ", escape="latex"
    )
    file_names.append("OpenVEX_repos.tex")
    content.append(
        styler.to_latex(
            environment="longtable",
            column_format="p{10cm}r",
            label="tab:OpenVEX repos",
            caption="Table naming repositories with OpenVEX files",
            hrules=True,
        )
    )

    SPDX_repos = repos.dropna(subset=["SPDX"])
    SPDX_repos.drop(columns=["CycloneDX", "OpenVEX", "CSAF"], inplace=True)
    styler = SPDX_repos.style.format(
        precision=2, decimal=",", thousands=" ", escape="latex"
    )
    file_names.append("SPDX_repos.tex")
    content.append(
        styler.to_latex(
            environment="longtable",
            column_format="p{10cm}r",
            label="tab:SPDX repos",
            caption="Table naming repositories with SPDX files",
            hrules=True,
        )
    )

    for file_name, content in zip(file_names, content):
        filepath = folder / file_name
        if not filepath.exists():
            filepath.touch()
        with filepath.open("w", encoding="utf-8") as file:
            file.write(content)
