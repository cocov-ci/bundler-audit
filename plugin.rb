require 'bundler/audit'
require 'bundler/audit/scanner'

# Mostly taken from https://github.com/rubysec/bundler-audit/blob/38dcacc9850dfd51bc563f4f3ed2d03709b45ecf/lib/bundler/audit/cli.rb

class BundlerAuditPlugin < Cocov::PluginKit::Run
  Database = Bundler::Audit::Database
  Scanner =  Bundler::Audit::Scanner
  GEM_DEP = /\A\s+([^\s]+)\s\(([^\)]+)\)\n?\z/

  def line_for_gem(path, gem)
    @lines ||= File.read(path).lines
    gem_version = gem.version.to_s
    gem_identifier = gem.identifier.map(&:to_s)[1..].join("-")

    1 + (@lines.index do |line|
      name, version = GEM_DEP.match(line)&.captures
      name == gem.name && (version == gem_version || version == gem_identifier)
    end || -1)
  end

  def run
    gem_lock = workdir.join("Gemfile.lock")
    if !File.exist?(gem_lock)
      puts "This plugin requires a Gemfile.lock to be present in the repository."
      exit 1
    end

    begin
      Database.download(path: Database.path, quiet: false)
    rescue Database::DownloadFailed => e
      puts "Failed downloading database: #{e}"
      # exit 1
    end

    database = Database.new(Database.path)
    scanner = begin
      Scanner.new(Dir.pwd, 'Gemfile.lock', database)
    rescue Bundler::GemfileLockNotFound => ex
      puts ex.message
      exit 1
    end

    scanner.report.each do |report|
      advisory = report.advisory
      gem = report.gem

      line = line_for_gem(gem_lock, gem)
      if line.zero?
        puts "Error: Cannot find line for gem #{gem}"
        exit 1
      end

      title = advisory.title

      solution = unless advisory.patched_versions.empty?
        patches = advisory.patched_versions.map { |v| "'#{v}'" }.join(', ')
        "Solution: Upgrade to #{patches}"
      else
        "No solution available."
      end

      url = advisory.url
      url = nil if url.empty?
      name = [advisory.cve_id, advisory.ghsa, "[No ID available]"]
        .compact
        .reject { _1.empty? }
        .first

      uid = sha1("security:#{gem.name}:#{gem.version.to_s}:#{name}")

      emit_issue(
        kind: :security,
        file: "Gemfile.lock",
        line_start: line,
        line_end: line,
        message: [
          "Vulnerability #{name} affects #{gem.name} version #{gem.version.to_s}: #{title}",
          url,
          solution,
        ].compact.join("\n"),
        uid: uid,
      )
    end
  end
end

Cocov::PluginKit.run(BundlerAuditPlugin)
