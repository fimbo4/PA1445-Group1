# Chapter 1
## Article 6
[Link](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32024R2847#art_6)
> (a) they meet the essential cybersecurity requirements set out in Part I of Annex I, provided that they are properly installed, maintained, used for their intended purpose or under conditions which can reasonably be foreseen, and, where applicable, the necessary security updates have been installed; and
>
> (b) the processes put in place by the manufacturer comply with the essential cybersecurity requirements set out in Part II of Annex I.

This is the lunchpin that enforces the reqirments. It also points us to where the requirments are. 

# Chapter 2
## Article 13
[Link](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32024R2847#art_13)
> 1.   When placing a product with digital elements on the market, manufacturers shall ensure that it has been designed, developed and produced in accordance with the essential cybersecurity requirements set out in Part I of Annex I.

Again Part I of Annex I. 

> 3.   The cybersecurity risk assessment shall be documented and updated as appropriate during a support period to be determined in accordance with paragraph 8 of this Article. That cybersecurity risk assessment shall comprise at least an analysis of cybersecurity risks based on the intended purpose and reasonably foreseeable use, as well as the conditions of use, of the product with digital elements, such as the operational environment or the assets to be protected, taking into account the length of time the product is expected to be in use. The cybersecurity risk assessment shall indicate whether and, if so in what manner, the security requirements set out in Part I, point (2), of Annex I are applicable to the relevant product with digital elements and how those requirements are implemented as informed by the cybersecurity risk assessment. It shall also indicate how the manufacturer is to apply Part I, point (1), of Annex I and the vulnerability handling requirements set out in Part II of Annex I.

This one basically says that you shall have an SBOM with a VEX. At least that is how I am interpriting it. 

> 5.   For the purpose of complying with paragraph 1, manufacturers shall exercise due diligence when integrating components sourced from third parties so that those components do not compromise the cybersecurity of the product with digital elements, including when integrating components of free and open-source software that have not been made available on the market in the course of a commercial activity.

Try at least

> 7.   The manufacturers shall systematically document, in a manner that is proportionate to the nature and the cybersecurity risks, relevant cybersecurity aspects concerning the products with digital elements, including vulnerabilities of which they become aware and any relevant information provided by third parties, and shall, where applicable, update the cybersecurity risk assessment of the products.

Keep updating the VEX. 

# Chapter 3
## Article 31
[Link](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32024R2847#art_31)
> 1.   The technical documentation shall contain all relevant data or details of the means used by the manufacturer to ensure that the product with digital elements and the processes put in place by the manufacturer comply with the essential cybersecurity requirements set out in Annex I. It shall at least contain the elements set out in Annex VII.

Vex is a part of the technical documentation I would think. 

> 2.   The technical documentation shall be drawn up before the product with digital elements is placed on the market and shall be continuously updated, where appropriate, at least during the support period.

Again, keep the Vex updated. 

# Annex I
## Part II
[Link](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32024R2847#anx_I)
>Manufacturers of products with digital elements shall:
>
>   (1) identify and document vulnerabilities and components contained in products with digital elements, including by drawing up a software bill of materials in a commonly used and machine-readable format covering at the very least the top-level dependencies of the products;

You have to have a minimum VEX. And an SBOM

