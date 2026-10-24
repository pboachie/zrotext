## 2024-05-18 - Strictly Bound Slice Lengths in JavaScript Parsing Loops
**Learning:** In JavaScript string/JSON parsing loops, using `Regex.exec(text.slice(at))` without an upper bound creates a new slice object spanning from the current index to the end of the string. On potentially large strings, this converts what should be an O(N) linear scan into an O(N^2) memory allocation bottleneck, degrading performance significantly on large payloads.
**Action:** Always strictly bound the slice length to the maximum expected token size (e.g., `text.slice(at, at + 129)` for a max 128-char token). This limits the slicing overhead from O(N) to O(1) space per match.

## 2024-05-19 - Fast template literal parsing
**Learning:** In Javascript environments (like Node.js or browsers), character-by-character string building within a `for` loop is extremely slow and acts as a significant bottleneck when rendering large text blocks.
**Action:** Replace single-character iteration and concatenation with `indexOf` to find the next structural boundary, then use `String.prototype.slice` to extract large string segments at once. When parsing token delimiters, always safely bound the `indexOf` lookup with the current index appropriately so an unmatched delimiter doesn't result in an infinite loop.
