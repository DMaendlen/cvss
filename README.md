# Simple CVSSv3.0 calculator

You need a CVSSv3.0 score? You don't want to (or cannot) use the online tool?
This script is for you.

## Usage
Make it executable (`chmod +x cvss.py`) and run it `./cvss.py`.

It will then collect the necessary information and return the desired values.

## Work in Progress
 * Currently, neither Temporal nor Environmental Scoring are implemented.
 * I'm not yet happy with the code, it looks ugly and needs refactoring.
 * If anybody has a better idea, how to collect the values on the cli, throw me
   a PR.
 * Tests are completely missing. Not sure how to implement those.
