# frozen_string_literal: true

# Run only against the newly installed archives, never the generated sources.
require "zrotext_sdk"

abort "unexpected SDK version" unless ZrotextSdk::VERSION == "0.1.0"
%w[zrotext-sdk tungsten-runtime].each do |name|
  spec = Gem.loaded_specs.fetch(name)
  root = File.realpath(spec.full_gem_path)
  home = File.realpath(ENV.fetch("GEM_HOME"))
  abort "gem outside isolated home" unless root.start_with?(home + File::SEPARATOR)

  # Installed gemspecs may omit spec.files; inspect installed library files.
  libraries = Dir.glob(File.join(root, "lib", "**", "*.rb"))
  abort "installed library is empty" if libraries.empty?
  libraries.each do |file|
    expected = File.realpath(file)
    suffix = "/" + file.delete_prefix(root + "/lib/")
    $LOADED_FEATURES.select { |path| path.end_with?(suffix) }.each do |loaded|
      abort "loaded outside installed gem" unless File.realpath(loaded) == expected
    end
  end
end
puts "Installed SDK and runtime loaded"
