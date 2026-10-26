## 2024-05-14 - Fast String Parsing
**Learning:** In Javascript, parsing string fields manually by reading character by character inside a `while` loop (using `text[at++]`) can be significantly slower than utilizing built-in functions like `indexOf`. When searching for a specific character like a quote (`"`), `text.indexOf('"', at)` allows the engine to use optimized native methods to find the index quickly, especially on larger inputs, providing measurable performance improvements for tokenizers/parsers.

**Action:** When implementing custom JSON parsing or tokenization logic, prefer built-in methods like `indexOf` over manual character-by-character loops when searching for delimiter characters.

## 2024-05-18 - Strictly Bound Slice Lengths in JavaScript Parsing Loops
**Learning:** In JavaScript string/JSON parsing loops, using `Regex.exec(text.slice(at))` without an upper bound creates a new slice object spanning from the current index to the end of the string. On potentially large strings, this converts what should be an O(N) linear scan into an O(N^2) memory allocation bottleneck, degrading performance significantly on large payloads.
**Action:** Always strictly bound the slice length to the maximum expected token size (e.g., `text.slice(at, at + 129)` for a max 128-char token). This limits the slicing overhead from O(N) to O(1) space per match.

## 2024-05-19 - Fast template literal parsing
**Learning:** In Javascript environments (like Node.js or browsers), character-by-character string building within a `for` loop is extremely slow and acts as a significant bottleneck when rendering large text blocks.
**Action:** Replace single-character iteration and concatenation with `indexOf` to find the next structural boundary, then use `String.prototype.slice` to extract large string segments at once. When parsing token delimiters, always safely bound the `indexOf` lookup with the current index appropriately so an unmatched delimiter doesn't result in an infinite loop.

## 2026-10-26 - Rust 1.99.1 Upgrade and Iterators
**Learning:** In the Zrotext Rust workspaces, blindly using `sed` or regex to refactor `.chunks_exact(N)` into the newly-recommended `as_chunks::<N>().0.iter()` (as suggested by the new Rust 1.99.1 clippy lint `chunks_exact_to_as_chunks`) causes massive cascading type failures. The new method produces an iterator over array references `&[u8; N]` instead of slice references `&[u8]`. This severely breaks down-stream method calls like `.collect::<Vec<_>>()` and `extend_from_slice()`.
**Action:** When migrating across this specific lint globally, it's safer and less invasive to use `#![allow(clippy::chunks_exact_to_as_chunks)]` on root modules rather than attempting automatic source-code regex refactoring which changes iterator types.
