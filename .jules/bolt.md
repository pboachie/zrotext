## 2024-05-14 - Fast String Parsing
**Learning:** In Javascript, parsing string fields manually by reading character by character inside a `while` loop (using `text[at++]`) can be significantly slower than utilizing built-in functions like `indexOf`. When searching for a specific character like a quote (`"`), `text.indexOf('"', at)` allows the engine to use optimized native methods to find the index quickly, especially on larger inputs, providing measurable performance improvements for tokenizers/parsers.

**Action:** When implementing custom JSON parsing or tokenization logic, prefer built-in methods like `indexOf` over manual character-by-character loops when searching for delimiter characters.
