# frozen_string_literal: true

# Standard-library-only tests of the actual validator used by CI, not a mirror.
require 'tmpdir'
require 'open3'
require 'rbconfig'
require_relative 'coderabbit_policy'

ROOT = File.expand_path('../..', __dir__)
SOURCE = File.read(File.join(ROOT, '.coderabbit.yaml'), encoding: 'UTF-8')
BASELINE = YAML.safe_load(SOURCE)
# Kept independent from the production constant to detect removed protection.
EXPECTED_PATHS = %w[
  .coderabbit.yaml .github/workflows/** .github/scripts/**
  .github/CODEOWNERS CODEOWNERS docs/CODEOWNERS
].freeze
$cases = 0


def verify(label)
  yield
  $cases += 1
  puts "PASS #{label}"
end


def changed
  value = Marshal.load(Marshal.dump(BASELINE))
  yield value
  YAML.dump(value)
end


def approval(value)
  value.fetch('reviews').fetch('auto_approvals')
end


def good(label, source)
  verify(label) { raise 'Validator did not return true' unless CodeRabbitPolicy.validate(source) == true }
end


def bad(label, source, message)
  verify(label) do
    begin
      CodeRabbitPolicy.validate(source)
    rescue CodeRabbitPolicy::Invalid => error
      raise "Unexpected rejection: #{error.message}" unless error.message.match?(message)
    else
      raise 'Invalid configuration was accepted'
    end
  end
end

begin
  good('checked-in configuration', SOURCE)
  good('serialization round trip', YAML.dump(BASELINE))
  good('explicitly disabled inheritance', changed { |c| c['inheritance'] = false })
  [true, nil, 'false'].each do |value|
    bad("unaudited inheritance rejects #{value.inspect}", changed { |c| c['inheritance'] = value }, /inheritance/)
  end
  good('comments and CRLF do not alter policy', ("# test\n" + SOURCE).gsub("\n", "\r\n"))
  %w[minimal low].each do |risk|
    good("second path override with #{risk} risk", changed do |c|
      approval(c)['overrides'] << {'paths' => ['README.md'], 'max_merge_risk' => risk, 'max_security_risk' => risk}
    end)
  end
  good('omitted override limits inherit low', changed { |c| approval(c)['overrides'] << {'paths' => ['README.md']} })
  good('valid team-scoped override retains unconditional protection', changed do |c|
    approval(c)['overrides'] << {'teams' => ['example/reviewers'], 'max_merge_risk' => 'minimal'}
  end)
  good('additional disabled scoped override', changed { |c| approval(c)['overrides'] << {'paths' => ['docs/**'], 'enabled' => false} })

  %w[max_merge_risk max_security_risk].each do |key|
    ['moderate', 'high', 'critical', 'LOW', 'Low', 'low ', "lo\u200bw", '', nil, false, 0, []].each do |risk|
      bad("global #{key} rejects #{risk.inspect}", changed { |c| approval(c)[key] = risk }, /#{key}/)
      bad("second override #{key} rejects #{risk.inspect}", changed do |c|
        approval(c)['overrides'] << {'paths' => ['README.md'], key => risk}
      end, /#{key}/)
    end
    bad("missing global #{key}", changed { |c| approval(c).delete(key) }, /#{key}/)
    bad("disabled override cannot carry latent high #{key}", changed do |c|
      approval(c)['overrides'][0][key] = 'high'
    end, /#{key}/)
  end

  [false, nil, 1, 'true', 'TRUE'].each do |value|
    bad("global enabled rejects #{value.inspect}", changed { |c| approval(c)['enabled'] = value }, /enabled/)
  end
  [true, nil, 0, 'false', 'FALSE'].each do |value|
    bad("author approval rejects #{value.inspect}", changed { |c| approval(c)['allow_author_approval'] = value }, /allow_author_approval/)
  end
  [true, nil, 0, 'false', 'true'].each do |value|
    bad("override enabled rejects #{value.inspect}", changed do |c|
      approval(c)['overrides'] << {'paths' => ['README.md'], 'enabled' => value}
    end, /enabled/)
  end

  {'Reviews' => 'reviews', 'reviews ' => 'reviews', "rev\u0456ews" => 'reviews'}.each do |wrong, correct|
    bad("root key #{wrong.inspect}", changed { |c| c[wrong] = c.delete(correct) }, /keys|identifiers/)
  end
  bad('review policy key casing', changed { |c| c['reviews']['Auto_Approvals'] = c['reviews'].delete('auto_approvals') }, /keys/)
  %w[Enabled Allow_Author_Approval max_merge_Risk max_security_Risk override].each do |wrong|
    bad("unknown approval key #{wrong}", changed { |c| approval(c)[wrong] = false }, /keys/)
    bad("unknown second override key #{wrong}", changed do |c|
      approval(c)['overrides'] << {'paths' => ['README.md'], wrong => false}
    end, /keys/)
  end
  bad('misnested author approval under reviews', changed { |c| c['reviews']['allow_author_approval'] = false }, /keys/)
  bad('legacy approval switch is not a substitute', changed { |c| c['reviews']['request_changes_workflow'] = true }, /keys/)

  EXPECTED_PATHS.each do |path|
    bad("missing protective path #{path}", changed { |c| approval(c)['overrides'][0]['paths'].delete(path) }, /sensitive path/)
    bad("incorrect path casing #{path}", changed do |c|
      paths = approval(c)['overrides'][0]['paths']
      paths[paths.index(path)] = path.swapcase
    end, /sensitive path/)
  end
  bad('protective override cannot be team-limited', changed { |c| approval(c)['overrides'][0]['teams'] = ['example/reviewers'] }, /unconditional/)
  bad('protective override cannot be enabled', changed { |c| approval(c)['overrides'][0]['enabled'] = true }, /enabled/)
  bad('protective override must explicitly be disabled', changed { |c| approval(c)['overrides'][0].delete('enabled') }, /unconditional/)
  bad('negation cannot carve out protective paths', changed { |c| approval(c)['overrides'][0]['paths'] << '!.github/workflows/**' }, /without exclusions/)
  [nil, false, {}, [], 'bad'].each do |value|
    bad("override collection rejects #{value.inspect}", changed { |c| approval(c)['overrides'] = value }, /overrides/)
  end
  [nil, false, 7, [], 'bad'].each do |value|
    bad("second override rejects #{value.inspect}", changed { |c| approval(c)['overrides'] << value }, /mapping/)
  end
  bad('unscoped override is not implicit global authority', changed { |c| approval(c)['overrides'] << {} }, /scope/)
  [nil, [], 'README.md', [''], [' README.md'], [false], ['README.md', 'README.md'], ["README.md\n"]].each do |value|
    bad("malformed paths #{value.inspect}", changed { |c| approval(c)['overrides'] << {'paths' => value} }, /paths/)
  end
  [nil, [], [false], ['reviewers'], ['example/reviewers '], ['example/my_team']].each do |value|
    bad("malformed team scope #{value.inspect}", changed { |c| approval(c)['overrides'] << {'teams' => value} }, /teams/)
  end
  bad('too many distinct teams', changed do |c|
    approval(c)['overrides'] << {'teams' => (1..16).map { |i| "example/team#{i}" }}
  end, /15 distinct teams/)

  bad('duplicate global key', SOURCE.sub('    max_merge_risk: low', "    max_merge_risk: high\n    max_merge_risk: low"), /duplicate key/)
  bad('duplicate override key', SOURCE.sub('      - enabled: false', "      - enabled: true\n        enabled: false"), /duplicate key/)
  bad('duplicate top-level mapping', SOURCE + "\nreviews: {}\n", /duplicate key/)
  %w[true false null Null].each do |key|
    bad("implicit non-string mapping key #{key}", SOURCE + "\nchat:\n  #{key}: ignored\n", /mapping keys/)
  end
  bad('extra YAML document', SOURCE + "\n---\nreviews: {}\n", /one YAML document/)
  bad('empty input', '', /one YAML document/)
  bad('sequence root', "- reviews\n", /mapping/)
  bad('syntax error', "reviews: [\n", /Invalid YAML/)
  bad('non-string mapping key', "? [reviews]\n: {}\n", /keys/)
  bad('YAML anchor', SOURCE.sub('reviews:', 'reviews: &policy'), /anchors/)
  bad('YAML alias', SOURCE.sub('    max_merge_risk: low', '    max_merge_risk: *risk'), /aliases/)
  bad('explicit YAML tag', SOURCE.sub('max_merge_risk: low', 'max_merge_risk: !!str low'), /tags/)
  bad('YAML merge key', SOURCE.sub('reviews:', "reviews:\n  <<: {}"), /merge keys/)
  %w[TRUE True yes YES on On].each do |value|
    bad("noncanonical boolean #{value}", SOURCE.sub('    enabled: true', "    enabled: #{value}"), /lowercase true/)
  end
  %w[FALSE False no NO off Off].each do |value|
    bad("noncanonical boolean #{value}", SOURCE.sub('    allow_author_approval: false', "    allow_author_approval: #{value}"), /lowercase true/)
  end
  bad('oversized YAML', '#' * (CodeRabbitPolicy::MAX_BYTES + 1), /size limit/)
  bad('invalid UTF-8', "\xff".b, /UTF-8/)
  bad('excessive nesting', "a:\n" + (1..40).map { |i| ('  ' * i) + "a:\n" }.join, /nesting limit/)

  # Preserve every previously enforced workflow invariant.
  [
    %w[reviews auto_review enabled],
    %w[reviews auto_review auto_incremental_review],
    %w[issue_enrichment auto_enrich enabled],
    %w[issue_enrichment planning enabled],
    %w[issue_enrichment planning auto_planning enabled],
    %w[reviews finishing_touches autofix enabled],
    %w[reviews finishing_touches fix_ci enabled],
    %w[reviews finishing_touches resolve_merge_conflict enabled]
  ].each do |keys|
    bad("preserved required setting #{keys.join('.')}", changed { |c| c.dig(*keys[0...-1])[keys[-1]] = false }, /#{keys[-2]}/)
  end
  ['0', 0.0, 1, nil].each do |value|
    bad("review pause exact integer rejects #{value.inspect}", changed { |c| c['reviews']['auto_review']['auto_pause_after_reviewed_commits'] = value }, /auto_pause_after_reviewed_commits/)
  end
  bad('branch coverage cannot shrink', changed { |c| c['reviews']['auto_review']['base_branches'] = ['master'] }, /all PR target branches/)
  bad('issue label mutation remains off', changed { |c| c['issue_enrichment']['labeling']['auto_apply_labels'] = true }, /auto_apply_labels/)

  # Exercise process exit status and ensure rejection cannot print the PASS marker.
  Dir.mktmpdir('coderabbit-policy-') do |dir|
    command = [RbConfig.ruby, File.join(__dir__, 'coderabbit_policy.rb')]
    file = File.join(dir, 'config.yaml')
    File.write(file, SOURCE)
    verify('CLI valid exit and message') do
      out, err, status = Open3.capture3(*command, file)
      raise "CLI failed: #{err}" unless status.success? && out.include?('safety gates: PASS')
    end
    File.write(file, SOURCE.sub('    max_merge_risk: low', '    max_merge_risk: high'))
    verify('CLI invalid exit and no success marker') do
      out, err, status = Open3.capture3(*command, file)
      raise 'CLI did not reject invalid config' unless status.exitstatus == 1 && err.include?('FAIL') && !out.include?('PASS')
    end
    verify('CLI missing file fails') do
      _, _, status = Open3.capture3(*command, File.join(dir, 'missing.yaml'))
      raise 'CLI accepted missing file' unless status.exitstatus == 1
    end
    File.symlink(file, File.join(dir, 'link.yaml'))
    verify('CLI symlink input fails') do
      _, err, status = Open3.capture3(*command, File.join(dir, 'link.yaml'))
      raise 'CLI accepted a symlink' unless status.exitstatus == 1 && err.include?('regular file')
    end
  end
  puts "Policy regression cases: #{$cases} PASS; 0 failures"
rescue StandardError => error
  warn "Policy regression failure after #{$cases} cases: #{error.class}: #{error.message}"
  exit 1
end
