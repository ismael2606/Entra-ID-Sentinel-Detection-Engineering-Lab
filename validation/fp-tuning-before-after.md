
# Validation — Password Spray detection

## Positive test
Spray (≥3 users fail from one source) → incident fired.
Evidence: evidence/m2-incident.png

## Negative test (false-positive control)
Single failed login (1 user) → logged in SigninLogs (1 distinct user) but returned
**zero rows** against the ≥3-distinct-user rule query → no incident raised.
Evidence: evidence/m2-negative-test.png (zero rows) + the 1-user confirmation.
Conclusion: the detection discriminates benign auth failures from spray attacks.

## Known tuning target (for later)
The rule bins failures into 10-min windows per IP. Repeated spray runs during testing
produced one incident *per bin*, i.e., multiple incidents for what was logically a few
campaigns. Tuning target: group into one incident per source per campaign to reduce
incident-queue noise. 
