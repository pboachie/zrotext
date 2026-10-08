## 2024-10-08 - Parallelizing Cryptographic Tasks
**Learning:** Found sequential `await` calls inside `for...of` loops handling cryptographic key deserialization in `sdk/typescript/src`.
**Action:** Replaced with `Promise.all` + `.map()` to enable parallel execution of these independent operations, significantly improving expected performance when dealing with multiple wraps.
