## 2025-02-18 - Bounding Regex Memory Allocations
**Learning:** In the custom JSON/text parsing loops inside `web/owner/account.js` and `web/owner/workflow-exceptions.js`, using a unbounded string slice (`text.slice(at)`) inside a `Regex.exec` over a long text can result in O(N^2) memory allocations. The browser creates an enormous sub-string on every iteration when matching numeric formats from a potentially huge dataset before it fails the max token length check. By bounding the slice length to the maximum token size (e.g. `text.slice(at, at + 129)`), execution time dropped significantly without altering parsing logic. Sticky regex (`/y`) is functionally better but requires instantiating/recreating the regex or managing global state carefully for concurrent parsers.
**Action:** Always bound string slicing operations inside loop bounds, or use `indexOf` / sticky regex when extracting tokens from highly repetitive or large payloads.

## 2024-05-14 - Fast String Parsing
**Learning:** In Javascript, parsing string fields manually by reading character by character inside a `while` loop (using `text[at++]`) can be significantly slower than utilizing built-in functions like `indexOf`. When searching for a specific character like a quote (`"`), `text.indexOf('"', at)` allows the engine to use optimized native methods to find the index quickly, especially on larger inputs, providing measurable performance improvements for tokenizers/parsers.

**Action:** When implementing custom JSON parsing or tokenization logic, prefer built-in methods like `indexOf` over manual character-by-character loops when searching for delimiter characters.

## 2024-05-18 - Strictly Bound Slice Lengths in JavaScript Parsing Loops
**Learning:** In JavaScript string/JSON parsing loops, using `Regex.exec(text.slice(at))` without an upper bound creates a new slice object spanning from the current index to the end of the string. On potentially large strings, this converts what should be an O(N) linear scan into an O(N^2) memory allocation bottleneck, degrading performance significantly on large payloads.
**Action:** Always strictly bound the slice length to the maximum expected token size (e.g., `text.slice(at, at + 129)` for a max 128-char token). This limits the slicing overhead from O(N) to O(1) space per match.

## 2024-05-19 - Fast template literal parsing
**Learning:** In Javascript environments (like Node.js or browsers), character-by-character string building within a `for` loop is extremely slow and acts as a significant bottleneck when rendering large text blocks.
**Action:** Replace single-character iteration and concatenation with `indexOf` to find the next structural boundary, then use `String.prototype.slice` to extract large string segments at once. When parsing token delimiters, always safely bound the `indexOf` lookup with the current index appropriately so an unmatched delimiter doesn't result in an infinite loop.
## 2024-10-30 - Faster String Parsing with indexOf
**Learning:** In Javascript/Typescript, parsing string fields manually by reading character by character inside a `while` loop (using `raw[at++]`) can be significantly slower than utilizing built-in functions like `indexOf`. Replacing it with `raw.indexOf('"', at)` allows the engine to use optimized native methods to find the index quickly, especially on larger inputs, providing measurable performance improvements for tokenizers/parsers.
**Action:** When implementing custom JSON parsing or tokenization logic, prefer built-in methods like `indexOf` over manual character-by-character loops when searching for delimiter characters.
