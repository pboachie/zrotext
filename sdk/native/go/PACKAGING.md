# Experimental installed webhook module

From the repository root, with Python 3.11+ and Go 1.22.12 on PATH:

```sh
python sdk/native/package-webhooks-native.py --language go --vectors REVIEWED_VECTOR_CHECKOUT --output NEW_OUTPUT_DIRECTORY
```

The helper requires the exact reviewed shared-vector checkout and a new output
directory outside the public checkout. The checkout supplies only TSV test data. It builds the experimental
`github.com/pboachie/zrotext/sdk/native/go` module `v0.1.0` with exactly four
entries: runtime source, go.mod, README and AGPL license. It removes the staged
library source before resolving a fresh consumer through an ordinary local
module proxy. The module has no third-party dependencies. No `replace`, private
checkout, workspace or preexisting module/build cache is used.
No Tungsten runtime or unpublished transitive module is required.

The installed consumer runs three existing native test groups and 16 shared
raw-byte signature/replay vectors. The negative signed-clock corpus case is
explicitly rejected during conversion to the public unsigned clock type; it
does not call the verifier. Existing maximum-unsigned-clock, exact body/key/time,
canonical headers and inclusive replay-window checks remain covered.

Outputs contain the licensed archive, consumer checksums and qualification
metadata. No module is published. Event-ID deduplication and receiver application
authorization are outside signature verification; archive acceptance does not
establish live webhook delivery or stable SDK replacement.
