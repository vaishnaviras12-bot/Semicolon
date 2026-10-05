// Single source of truth for citations. NewsArticle.jsx cites a subset of
// these inline (by id) and renders a matching local footnote list; References.jsx
// renders the full list. Numbering is derived from array order in both places,
// so the two pages can't drift the way they had when each hardcoded its own copy.
export const REFERENCES = [
  {
    id: 1,
    title: 'Towards a Unified Quantum Risk Assessment',
    authors: 'Grigaliūnas, Š. & Brūzgienė, R. (2025)',
    venue: 'Electronics, 14(17), 3338 (MDPI)',
    url: 'https://doi.org/10.3390/electronics14173338',
    note: "Introduces QARS (Quantum-Adjusted Risk Score), extending Mosca's inequality into a multi-factor timeline / sensitivity / exposure scoring model.",
  },
  {
    id: 2,
    title: 'A Quantum-Adjusted Risk Model for Enterprise Infrastructure Across Data In Transit, In Use, and At Rest',
    authors: 'Krušniauskas, S., Grigaliūnas, Š., Brūzgienė, R. & Cayir, M. (2026)',
    venue: 'Electronics, 15(12), 2546 (MDPI)',
    url: 'https://doi.org/10.3390/electronics15122546',
    note: 'Extends QARS into a layer-specific model (in transit / in use / at rest) with a Shor-vs-Grover attenuation mechanism — directly informed the risk model used in this build.',
  },
  {
    id: 3,
    title: 'CARAF: Crypto Agility Risk Assessment Framework',
    authors: 'Ma, C., Colon, L., Dera, J., Rashidi, B. & Garg, V. (2021)',
    venue: 'Journal of Cybersecurity, 7(1), tyab013',
    url: 'https://academic.oup.com/cybersecurity/article/7/1/tyab013/6289827',
    note: 'A 5-phase framework (threat identification → asset inventory → risk estimation → mitigation → roadmap) for assessing the risk of lacking crypto-agility, demonstrated on a quantum-computing case study.',
  },
  {
    id: 4,
    title: "Refining Mosca's Theorem: Risk Management Model for the Quantum Threat Applied to IoT Protocol Security",
    authors: 'Kiviharju, M. (2022)',
    venue: 'In Cyber Security, pp. 369–401 (Springer, Cham)',
    url: 'https://doi.org/10.1007/978-3-030-91293-2_16',
    note: "Extends Mosca's XYZ timeline model into a more detailed risk framework, applied across 17 IoT protocol families.",
  },
  {
    id: 5,
    title: 'Survey on post-quantum cryptography implementations and deployment challenges',
    authors: 'Sakwa, C.O. & Li, F. (2026)',
    venue: 'Computer Science Review, 61, 100975 (Elsevier)',
    url: 'https://share.google/hJc3mc3cjogIqFIW1',
    note: 'Implementation-focused survey of NIST-standardized PQC algorithms (ML-KEM/Kyber, ML-DSA/Dilithium, FALCON, SPHINCS+, HQC) across CPUs, GPUs, FPGAs, and microcontrollers, and deployment pathways for TLS, VPNs, and blockchain infrastructure.',
  },
  {
    id: 6,
    title: 'SP 1800-38, Migration to Post-Quantum Cryptography: Preparation for Considering the Implementation and Adoption of Quantum Safe Cryptography (Preliminary Draft)',
    authors: 'Newhouse, W., Souppaya, M., Barker, W. & Brown, C. — NIST National Cybersecurity Center of Excellence (2023)',
    venue: 'NIST Special Publication 1800-38',
    url: 'https://csrc.nist.gov/pubs/sp/1800/38/iprd',
    note: 'NCCoE project guidance on preparing for post-quantum migration. Note: this specific preliminary draft has since been superseded by later drafts in the same series on NIST\u2019s site.',
  },
];

// Provided but not confirmed in this pass — listed as given rather than
// dropped or described from guesswork.
export const UNVERIFIED_REFERENCES = [
  { url: 'https://share.google/fUbWYbNVjumRa3zOz' },
  { url: 'https://doi.org/10.3390/computers15080495' },
  { url: 'https://eprint.iacr.org/2026/1938' },
  { url: 'https://arxiv.org/abs/2606.13425' },
  { url: 'https://arxiv.org/abs/2604.21436' },
];

export function getReference(id) {
  return REFERENCES.find((r) => r.id === id);
}
