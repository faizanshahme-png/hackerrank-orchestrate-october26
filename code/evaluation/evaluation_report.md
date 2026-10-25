# Evaluation report

## Final full-dataset run

Command: `c:/python313/python.exe -u code/main.py`

- Input requests: 518
- Output rows: 518
- Elapsed time: 817.2 seconds (13.6 minutes)
- Model: Ollama `llama3.2:3b`, two workers, 45-second request timeout, maximum two generations per reviewed case
- Model generations: 117 total (one startup diagnostic and 116 case generations)
- Registered tool actions: 1,255
- Agent failures: 0
- Status distribution: 153 `COMPLETE`, 334 `INCOMPLETE`, 31 `NOT_APPLICABLE`
- Atomic output write: completed only after temporary-file validation

## Independent structural and substantive checks

The independent validator re-read the generated root `output.csv`: 518 rows, complete and unique case IDs, exact header and column order, valid JSON arrays, consecutive step numbers, allowed phases/operations/states, phase ordering, valid evidence references, cutoff-eligible evidence, and correct empty evidence IDs for future actions. It reported **0 errors**. Structural validation does not prove every substantive interpretation; evidence provenance and policy reconciliation remain enforced during investigation.

## Public sample regression

The 32 sample IDs are not present in the 518-row evaluation request file, so direct row intersection is empty. The sample requests were independently re-investigated with the same evidence/policy engine. Results: status agreement **31/32** and exact step-array agreement **0/32**. The status mismatch is `case_07`; its expected support attachment is an image-style PDF whose text is not extractable in the installed environment. Step arrays differ because the generic participant-visible evidence scan does not reproduce the organizer's resource-selection decisions for every sample. No sample answer is copied into the full output.

## Focused tests and live probes

`c:/python313/python.exe -m unittest discover -s code -p 'test_*.py' -v` passed **6/6** tests. They cover non-deletion classification, invalid tool schemas, malformed model handling, operation/state mapping, a model-supported output change from retrieved activity evidence, and resource-system mapping. A live probe of the five cases that failed during the first full pass passed after the bounded follow-up and provenance fixes. Mocked/unit tests are not counted as live model calls.

## Performance failures and improvements

The initial optimized run reached all 518 cases in 1,997.7 seconds but correctly preserved the prior output after five model failures: one follow-up request under a one-call bound and four unusable evidence citations. The final implementation allows one optional follow-up, records invalid-tool responses, binds only to retrieved evidence, and records a warning when no eligible evidence exists. The rerun completed all cases in 817.2 seconds with no failures.

## Additional evaluation cases

1. A Japanese deletion request is recognized as authorized and filtered at its audit cutoff.
2. An account tombstone preserves the stable reference while direct identifiers require redaction.
3. A request containing access/correction language is `NOT_APPLICABLE` with `[]`.
4. An active data-flow observation produces a finding, disable remediation, and disabled verification in the required phase order.
