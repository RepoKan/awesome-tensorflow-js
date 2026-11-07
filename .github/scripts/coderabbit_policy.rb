# frozen_string_literal: true

require 'yaml'

# A deterministic repository policy check, not independent merge authorization.
# This file is PR-controlled; protected-branch rules still govern its adoption.
module CodeRabbitPolicy
  class Invalid < StandardError; end

  MAX_BYTES = 131_072
  MAX_DEPTH = 32
  LOW_RISKS = %w[minimal low].freeze
  SENSITIVE_PATHS = %w[
    .coderabbit.yaml .github/workflows/** .github/scripts/**
    .github/CODEOWNERS CODEOWNERS docs/CODEOWNERS
  ].freeze
  ROOT_KEYS = %w[
    language tone_instructions early_access enable_free_tier inheritance
    reviews chat knowledge_base code_generation issue_enrichment
  ].freeze
  REVIEW_KEYS = %w[
    profile high_level_summary high_level_summary_instructions
    high_level_summary_placeholder high_level_summary_in_walkthrough
    auto_title_placeholder auto_title_instructions review_status review_info
    review_details review_progress commit_status fail_commit_status
    collapse_walkthrough changed_files_summary sequence_diagrams
    estimate_code_review_effort assess_linked_issues related_issues related_prs
    suggested_labels labeling_instructions mutually_exclusive_groups
    auto_apply_labels suggested_reviewers auto_assign_reviewers
    suggested_reviewers_instructions in_progress_fortune poem
    enable_prompt_for_ai_agents path_filters path_instructions abort_on_close
    disable_cache post_merge_actions auto_approvals slop_detection auto_review
    finishing_touches pre_merge_checks tools
  ].freeze
  AUTO_REVIEW_KEYS = %w[
    enabled description_keyword auto_incremental_review
    auto_pause_after_reviewed_commits ignore_title_keywords labels drafts
    base_branches ignore_usernames
  ].freeze
  APPROVAL_KEYS = %w[
    enabled allow_author_approval max_merge_risk max_security_risk overrides
  ].freeze
  OVERRIDE_KEYS = %w[enabled teams paths max_merge_risk max_security_risk].freeze

  module_function

  def check(condition, message)
    raise Invalid, message unless condition
  end

  def mapping(value, path, allowed = nil)
    check(value.is_a?(Hash), "#{path}: expected a mapping")
    check(value.keys.all? { |key| key.is_a?(String) }, "#{path}: keys must be strings")
    if allowed
      unknown = value.keys - allowed
      check(unknown.empty?, "#{path}: unknown or incorrectly cased keys #{unknown.inspect}")
    end
    value
  end

  def exact(value, expected, path)
    check(value.class == expected.class && value == expected,
          "#{path}: must be #{expected.inspect} (#{expected.class}); case and type are exact")
  end

  def string_list(value, path, nonempty: true)
    check(value.is_a?(Array) && (!nonempty || !value.empty?), "#{path}: expected a string list")
    check(value.all? { |item| item.is_a?(String) && !item.empty? &&
      item == item.strip && !item.match?(/[\x00-\x1f\x7f]/) },
          "#{path}: entries must be nonempty strings without surrounding whitespace or controls")
    check(value.uniq.length == value.length, "#{path}: duplicate entries are not allowed")
    value
  end

  # Reject ambiguity before safe_load can discard duplicate keys or extra documents.
  def inspect_node(node, path = '$', depth = 0)
    check(depth <= MAX_DEPTH, "#{path}: YAML nesting limit exceeded")
    check(!node.is_a?(Psych::Nodes::Alias), "#{path}: YAML aliases are not allowed")
    check(!node.respond_to?(:anchor) || node.anchor.nil?, "#{path}: YAML anchors are not allowed")
    check(!node.respond_to?(:tag) || node.tag.nil?, "#{path}: explicit YAML tags are not allowed")
    case node
    when Psych::Nodes::Mapping
      seen = {}
      node.children.each_slice(2) do |key, value|
        check(key.is_a?(Psych::Nodes::Scalar), "#{path}: mapping keys must be scalars")
        name = key.value
        check(!key.plain || !name.match?(/\A(?:true|false|null|yes|no|on|off|y|n)\z/i),
              "#{path}: boolean/null-like mapping keys must be quoted strings")
        check(name != '<<', "#{path}: YAML merge keys are not allowed")
        check(name.ascii_only? && name.match?(/\A[A-Za-z_][A-Za-z0-9_-]*\z/),
              "#{path}: mapping keys must be exact ASCII identifiers")
        check(!seen.key?(name), "#{path}: duplicate key #{name.inspect}")
        seen[name] = true
        inspect_node(key, "#{path}.#{name} (key)", depth + 1)
        inspect_node(value, "#{path}.#{name}", depth + 1)
      end
    when Psych::Nodes::Scalar
      if node.plain && node.value.match?(/\A(?:true|false|yes|no|on|off|y|n)\z/i)
        check(%w[true false].include?(node.value),
              "#{path}: use lowercase true/false for booleans; quote literal strings")
      end
    else
      (node.children || []).each_with_index { |child, i| inspect_node(child, "#{path}[#{i}]", depth + 1) }
    end
  end

  def parse(source)
    check(source.is_a?(String) && source.bytesize <= MAX_BYTES, 'YAML input exceeds size limit')
    source = source.dup.force_encoding(Encoding::UTF_8)
    check(source.valid_encoding?, 'YAML input must be valid UTF-8')
    stream = Psych.parse_stream(source)
    check(stream.children.length == 1, 'Exactly one YAML document is required')
    document = stream.children.first
    check(document.root.is_a?(Psych::Nodes::Mapping), 'Configuration must be a mapping')
    inspect_node(document.root)
    YAML.safe_load(source, permitted_classes: [], permitted_symbols: [], aliases: false)
  rescue Psych::Exception => e
    raise Invalid, "Invalid YAML: #{e.message}"
  end

  def validate_overrides(approvals)
    overrides = approvals['overrides']
    check(overrides.is_a?(Array) && !overrides.empty?, 'Approval overrides must be a nonempty list')
    overrides.each_with_index do |rule, i|
      path = "reviews.auto_approvals.overrides[#{i}]"
      mapping(rule, path, OVERRIDE_KEYS)
      if rule.key?('enabled')
        exact(rule['enabled'], false, "#{path}.enabled")
      end
      # Omitted risk fields inherit the global low limit. Explicit null, unknown,
      # incorrectly cased and risk-raising values fail, even on disabled rules.
      %w[max_merge_risk max_security_risk].each do |key|
        next unless rule.key?(key)
        check(rule[key].is_a?(String) && LOW_RISKS.include?(rule[key]),
              "#{path}.#{key}: only minimal or low is allowed; omit to inherit")
      end
      check(rule.key?('paths') || rule.key?('teams'), "#{path}: an explicit nonempty scope is required")
      string_list(rule['paths'], "#{path}.paths") if rule.key?('paths')
      if rule.key?('teams')
        teams = string_list(rule['teams'], "#{path}.teams")
        check(teams.all? { |team| team.match?(/\A[A-Za-z0-9][A-Za-z0-9-]*\/[A-Za-z0-9][A-Za-z0-9-]*\z/) },
              "#{path}.teams: use organization/team-slug")
      end
    end
    teams = overrides.flat_map { |rule| rule.fetch('teams', []) }.uniq
    check(teams.length <= 15, 'Approval overrides may refer to at most 15 distinct teams')
    protective = overrides.any? do |rule|
      rule['enabled'].equal?(false) && !rule.key?('teams') && rule['paths'].is_a?(Array) &&
        (SENSITIVE_PATHS - rule['paths']).empty? && rule['paths'].none? { |path| path.start_with?('!') }
    end
    check(protective, 'An unconditional disabled override must explicitly cover every sensitive path without exclusions')
  end

  def validate(source)
    config = mapping(parse(source), '$', ROOT_KEYS)
    # The gate cannot audit policy inherited from an external configuration.
    exact(config['inheritance'], false, 'inheritance') if config.key?('inheritance')
    reviews = mapping(config['reviews'], 'reviews', REVIEW_KEYS)
    automatic = mapping(reviews['auto_review'], 'reviews.auto_review', AUTO_REVIEW_KEYS)
    approvals = mapping(reviews['auto_approvals'], 'reviews.auto_approvals', APPROVAL_KEYS)
    exact(automatic['enabled'], true, 'reviews.auto_review.enabled')
    exact(approvals['enabled'], true, 'reviews.auto_approvals.enabled')
    exact(approvals['allow_author_approval'], false, 'reviews.auto_approvals.allow_author_approval')
    %w[max_merge_risk max_security_risk].each { |key| exact(approvals[key], 'low', "reviews.auto_approvals.#{key}") }
    validate_overrides(approvals)
    exact(automatic['auto_incremental_review'], true, 'reviews.auto_review.auto_incremental_review')
    exact(automatic['auto_pause_after_reviewed_commits'], 0, 'reviews.auto_review.auto_pause_after_reviewed_commits')
    branches = string_list(automatic['base_branches'], 'reviews.auto_review.base_branches')
    check(branches.include?('.*'), 'Reviews must cover all PR target branches')
    issues = mapping(config['issue_enrichment'], 'issue_enrichment')
    enrich = mapping(issues['auto_enrich'], 'issue_enrichment.auto_enrich')
    planning = mapping(issues['planning'], 'issue_enrichment.planning')
    auto_planning = mapping(planning['auto_planning'], 'issue_enrichment.planning.auto_planning')
    labeling = mapping(issues['labeling'], 'issue_enrichment.labeling')
    exact(enrich['enabled'], true, 'issue_enrichment.auto_enrich.enabled')
    exact(planning['enabled'], true, 'issue_enrichment.planning.enabled')
    exact(auto_planning['enabled'], true, 'issue_enrichment.planning.auto_planning.enabled')
    exact(labeling['auto_apply_labels'], false, 'issue_enrichment.labeling.auto_apply_labels')
    fixes = mapping(reviews['finishing_touches'], 'reviews.finishing_touches')
    %w[autofix fix_ci resolve_merge_conflict].each do |key|
      setting = mapping(fixes[key], "reviews.finishing_touches.#{key}")
      exact(setting['enabled'], true, "reviews.finishing_touches.#{key}.enabled")
    end
    true
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    raise CodeRabbitPolicy::Invalid, 'Usage: ruby coderabbit_policy.rb [configuration.yaml]' if ARGV.length > 1
    path = ARGV.first || '.coderabbit.yaml'
    raise CodeRabbitPolicy::Invalid, 'Configuration must be a regular file, not a symlink' unless File.lstat(path).file?
    # Bound the actual read, not just a separate stat that could become stale.
    source = File.open(path, 'rb') { |file| file.read(CodeRabbitPolicy::MAX_BYTES + 1) }
    CodeRabbitPolicy.validate(source)
    puts 'CodeRabbit YAML and safety gates: PASS'
  rescue CodeRabbitPolicy::Invalid, SystemCallError => e
    warn "CodeRabbit policy: FAIL: #{e.message}"
    exit 1
  end
end
