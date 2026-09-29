# R8 rules for the release APK. AndroidX, Compose, Room and OkHttp ship their
# own consumer rules, and the manifest keeps every declared component.

# The source is public, so renaming classes hides nothing. Keeping the original
# names leaves release stack traces and the class names in gateway logs
# readable without a separate mapping file. R8 still removes unused code and
# resources and optimizes what remains.
-dontobfuscate
