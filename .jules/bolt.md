## 2024-05-14 - Fast String Parsing
**Learning:** In Javascript, parsing string fields manually by reading character by character inside a `while` loop (using `text[at++]`) can be significantly slower than utilizing built-in functions like `indexOf`. When searching for a specific character like a quote (`"`), `text.indexOf('"', at)` allows the engine to use optimized native methods to find the index quickly, especially on larger inputs, providing measurable performance improvements for tokenizers/parsers.

**Action:** When implementing custom JSON parsing or tokenization logic, prefer built-in methods like `indexOf` over manual character-by-character loops when searching for delimiter characters.

## 2024-05-18 - Strictly Bound Slice Lengths in JavaScript Parsing Loops
**Learning:** In JavaScript string/JSON parsing loops, using `Regex.exec(text.slice(at))` without an upper bound creates a new slice object spanning from the current index to the end of the string. On potentially large strings, this converts what should be an O(N) linear scan into an O(N^2) memory allocation bottleneck, degrading performance significantly on large payloads.
**Action:** Always strictly bound the slice length to the maximum expected token size (e.g., `text.slice(at, at + 129)` for a max 128-char token). This limits the slicing overhead from O(N) to O(1) space per match.
