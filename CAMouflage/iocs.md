# CAMouflage - Indicators

The detailed hashes, filenames, delivery infrastructure, and C2 enrichment for this Sherlock are documented in:

- [CAMouflage overview](./README.md)
- [Malware analysis](./malware-analysis.md)
- [Timeline](./timeline.md)

## Evidence boundary

The repository distinguishes between indicators recovered directly from the supplied KAPE artifacts and indicators obtained through external threat-intelligence enrichment tied to the exact reconstructed sample.

In particular, the final C2 domain was not recovered in clear text from the retained disk artifacts; it was identified through a sample-hash pivot and is documented with that caveat in the main analysis.
