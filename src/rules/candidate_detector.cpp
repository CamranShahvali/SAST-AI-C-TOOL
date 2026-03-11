#include "sast/rules/candidate_detector.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <regex>
#include <sstream>
#include <unordered_set>

namespace sast::rules {

namespace {

struct ExpressionResolution {
  std::string summary;
  std::vector<std::string> trace_steps;
  std::vector<ir::SourceLocation> evidence_locations;
};

std::string trim(const std::string& value) {
  const auto first = value.find_first_not_of(" \t\r\n");
  if (first == std::string::npos) {
    return {};
  }
  const auto last = value.find_last_not_of(" \t\r\n");
  return value.substr(first, last - first + 1);
}

bool is_identifier_char(const char ch) {
  return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
         (ch >= '0' && ch <= '9') || ch == '_';
}

bool contains_token(const std::string& text, const std::string& token) {
  if (token.empty()) {
    return false;
  }

  std::size_t position = text.find(token);
  while (position != std::string::npos) {
    const auto left_ok = position == 0 || !is_identifier_char(text[position - 1]);
    const auto right_index = position + token.size();
    const auto right_ok = right_index >= text.size() || !is_identifier_char(text[right_index]);
    if (left_ok && right_ok) {
      return true;
    }
    position = text.find(token, position + token.size());
  }
  return false;
}

std::vector<std::string> name_variants(const std::string& name) {
  std::vector<std::string> variants;
  if (name.empty()) {
    return variants;
  }

  variants.push_back(name);
  if (name.starts_with("::")) {
    variants.push_back(name.substr(2));
  } else {
    variants.push_back("::" + name);
  }

  const auto last_component = name.rfind("::");
  if (last_component != std::string::npos && last_component + 2 < name.size()) {
    variants.push_back(name.substr(last_component + 2));
  }

  std::sort(variants.begin(), variants.end());
  variants.erase(std::unique(variants.begin(), variants.end()), variants.end());
  return variants;
}

template <typename Predicate>
bool matches_any_variant(const std::string& name, Predicate&& predicate) {
  for (const auto& variant : name_variants(name)) {
    if (predicate(variant)) {
      return true;
    }
  }
  return false;
}

std::optional<std::string> sink_family(
  const SourceSinkRegistry& registry,
  const std::string& callee) {
  if (matches_any_variant(callee, [&](const std::string& value) {
        return registry.is_command_sink(value);
      })) {
    return "command_injection";
  }
  if (matches_any_variant(callee, [&](const std::string& value) {
        return registry.is_path_sink(value);
      })) {
    return "path_traversal";
  }
  if (matches_any_variant(callee, [&](const std::string& value) {
        return registry.is_string_sink(value);
      })) {
    return "dangerous_string";
  }
  return std::nullopt;
}

bool matches_registry_function(
  const SourceSinkRegistry& registry,
  const std::string& callee,
  const std::string& family) {
  if (family == "allowlist") {
    return matches_any_variant(callee, [&](const std::string& value) {
      return registry.is_allowlist_predicate(value);
    });
  }
  if (family == "sanitizer") {
    return matches_any_variant(callee, [&](const std::string& value) {
      return registry.is_sanitizer_function(value) || registry.is_path_sanitizer(value);
    });
  }
  if (family == "trusted_wrapper") {
    return matches_any_variant(callee, [&](const std::string& value) {
      return registry.is_trusted_wrapper(value);
    });
  }
  return false;
}

std::string join_arguments(const std::vector<std::string>& arguments) {
  std::ostringstream stream;
  for (std::size_t index = 0; index < arguments.size(); ++index) {
    if (index > 0) {
      stream << ", ";
    }
    stream << trim(arguments[index]);
  }
  return stream.str();
}

std::uint64_t fnv1a64(const std::string& value) {
  std::uint64_t hash = 14695981039346656037ull;
  for (const auto ch : value) {
    hash ^= static_cast<unsigned char>(ch);
    hash *= 1099511628211ull;
  }
  return hash;
}

std::string hex_id(const std::uint64_t value) {
  std::ostringstream stream;
  stream << std::hex << value;
  return stream.str();
}

void append_trace(
  std::vector<std::string>& destination,
  const std::string& step) {
  if (step.empty()) {
    return;
  }
  if (std::find(destination.begin(), destination.end(), step) == destination.end()) {
    destination.push_back(step);
  }
}

void append_location(
  std::vector<ir::SourceLocation>& destination,
  const ir::SourceLocation& location) {
  if (!location.valid()) {
    return;
  }
  const auto already_present = std::find_if(
    destination.begin(),
    destination.end(),
    [&](const ir::SourceLocation& existing) {
      return existing.file == location.file &&
             existing.line == location.line &&
             existing.column == location.column;
    });
  if (already_present == destination.end()) {
    destination.push_back(location);
  }
}

std::vector<std::string> extract_called_names(const std::string& expression) {
  static const std::regex call_regex(R"(([A-Za-z_][A-Za-z0-9_:]*)\s*\()");
  std::vector<std::string> names;
  for (std::sregex_iterator iterator(expression.begin(), expression.end(), call_regex), end;
       iterator != end;
       ++iterator) {
    names.push_back((*iterator)[1].str());
  }
  return names;
}

std::optional<std::string> base_identifier(
  const std::string& expression,
  const SourceSinkRegistry& registry) {
  static const std::regex accessor_regex(
    R"(([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\))");
  std::smatch accessor_match;
  if (std::regex_search(expression, accessor_match, accessor_regex)) {
    const auto accessor = accessor_match[2].str();
    if (registry.is_trusted_accessor(accessor)) {
      return accessor_match[1].str();
    }
  }

  static const std::regex identifier_regex(R"(^[\s*&]*([A-Za-z_][A-Za-z0-9_]*)[\s]*$)");
  std::smatch identifier_match;
  if (std::regex_match(expression, identifier_match, identifier_regex)) {
    return identifier_match[1].str();
  }
  return std::nullopt;
}

std::string normalize_initializer_text(
  const std::string& variable_name,
  const std::string& initializer_text) {
  const auto normalized = trim(initializer_text);
  if (normalized.size() > variable_name.size() + 2 &&
      normalized.starts_with(variable_name) &&
      normalized[variable_name.size()] == '(' &&
      normalized.back() == ')') {
    return trim(normalized.substr(
      variable_name.size() + 1,
      normalized.size() - variable_name.size() - 2));
  }
  if (normalized.size() > variable_name.size() + 2 &&
      normalized.starts_with(variable_name) &&
      normalized[variable_name.size()] == '{' &&
      normalized.back() == '}') {
    return trim(normalized.substr(
      variable_name.size() + 1,
      normalized.size() - variable_name.size() - 2));
  }
  return normalized;
}

const ir::VariableDef* find_variable_def(
  const ir::Function& function,
  const std::string& name) {
  for (const auto& variable_def : function.variable_defs) {
    if (variable_def.name == name) {
      return &variable_def;
    }
  }
  return nullptr;
}

std::optional<std::size_t> destination_extent_for_argument(
  const ir::Function& function,
  const SourceSinkRegistry& registry,
  const std::string& expression) {
  const auto identifier = base_identifier(trim(expression), registry);
  if (!identifier) {
    return std::nullopt;
  }
  if (const auto* variable_def = find_variable_def(function, *identifier)) {
    return variable_def->static_extent;
  }
  return std::nullopt;
}

ExpressionResolution resolve_expression(
  const ir::Function& function,
  const std::string& expression,
  const SourceSinkRegistry& registry,
  std::unordered_set<std::string>& visited_variables) {
  ExpressionResolution result;
  const auto normalized = trim(expression);
  if (normalized.empty()) {
    result.summary = "unknown";
    return result;
  }

  result.summary = normalized;

  for (const auto& called_name : extract_called_names(normalized)) {
    if (matches_any_variant(called_name, [&](const std::string& value) {
          return registry.is_source_function(value);
        })) {
      append_trace(result.trace_steps, "expression calls configured source " + called_name);
    } else if (matches_registry_function(registry, called_name, "sanitizer")) {
      append_trace(result.trace_steps, "expression flows through configured sanitizer " + called_name);
    } else if (matches_registry_function(registry, called_name, "trusted_wrapper")) {
      append_trace(result.trace_steps, "expression flows through configured trusted wrapper " + called_name);
    } else if (!registry.is_trusted_accessor(called_name)) {
      append_trace(result.trace_steps, "expression includes unmodeled helper call " + called_name);
    }
  }

  for (const auto& parameter_name : function.parameter_names) {
    if (parameter_name.empty() || parameter_name == "argc") {
      continue;
    }
    if (contains_token(normalized, parameter_name)) {
      append_trace(result.trace_steps, "expression depends on parameter " + parameter_name);
    }
  }

  if (contains_token(normalized, "argv")) {
    append_trace(result.trace_steps, "expression references argv");
  }

  const auto identifier = base_identifier(normalized, registry);
  if (identifier && !visited_variables.contains(*identifier)) {
    if (const auto* variable_def = find_variable_def(function, *identifier)) {
      visited_variables.insert(*identifier);
      append_location(result.evidence_locations, variable_def->location);
      if (!variable_def->initializer_text.empty()) {
        const auto normalized_initializer =
          normalize_initializer_text(*identifier, variable_def->initializer_text);
        append_trace(
          result.trace_steps,
          "value resolves through local " + *identifier + " = " + normalized_initializer);
        auto nested = resolve_expression(
          function,
          normalized_initializer,
          registry,
          visited_variables);
        if (!nested.summary.empty()) {
          result.summary = nested.summary;
        }
        for (const auto& step : nested.trace_steps) {
          append_trace(result.trace_steps, step);
        }
        for (const auto& location : nested.evidence_locations) {
          append_location(result.evidence_locations, location);
        }
      } else if (variable_def->static_extent) {
        result.summary = *identifier;
        append_trace(
          result.trace_steps,
          "local " + *identifier + " has static extent " +
            std::to_string(*variable_def->static_extent));
      }
    }
  }

  return result;
}

void append_related_context(
  const ir::Function& function,
  const SourceSinkRegistry& registry,
  const std::string& tracked_identifier,
  std::vector<std::string>& trace_steps,
  std::vector<ir::SourceLocation>& evidence_locations) {
  if (tracked_identifier.empty()) {
    return;
  }

  for (const auto& call : function.call_sites) {
    bool references_identifier = false;
    for (const auto& argument : call.argument_texts) {
      if (contains_token(argument, tracked_identifier)) {
        references_identifier = true;
        break;
      }
    }
    if (!references_identifier) {
      continue;
    }

    if (matches_registry_function(registry, call.callee, "allowlist")) {
      append_trace(trace_steps, "allowlist predicate " + call.callee + " observed for " + tracked_identifier);
      append_location(evidence_locations, call.location);
    } else if (matches_registry_function(registry, call.callee, "sanitizer")) {
      append_trace(trace_steps, "sanitizer " + call.callee + " observed for " + tracked_identifier);
      append_location(evidence_locations, call.location);
    } else if (matches_registry_function(registry, call.callee, "trusted_wrapper")) {
      append_trace(trace_steps, "trusted wrapper " + call.callee + " observed for " + tracked_identifier);
      append_location(evidence_locations, call.location);
    }
  }
}

std::size_t source_argument_index(
  const std::string& family,
  const std::string& sink_name,
  const std::vector<std::string>& arguments) {
  if (arguments.empty()) {
    return 0;
  }
  if (family == "command_injection" || family == "path_traversal") {
    return 0;
  }

  const auto last_component = sink_name.rfind("::");
  const auto unqualified = last_component == std::string::npos
                             ? sink_name
                             : sink_name.substr(last_component + 2);
  if ((unqualified == "sprintf" || unqualified == "vsprintf") && arguments.size() > 2) {
    return 2;
  }
  if ((unqualified == "snprintf" || unqualified == "vsnprintf") && arguments.size() > 3) {
    return 3;
  }
  if ((unqualified == "strcpy" || unqualified == "strcat") && arguments.size() > 1) {
    return 1;
  }
  if (arguments.size() > 1) {
    return 1;
  }
  return 0;
}

std::string bound_expression(
  const std::string& sink_name,
  const std::vector<std::string>& arguments) {
  if (arguments.empty()) {
    return {};
  }

  const auto last_component = sink_name.rfind("::");
  const auto unqualified = last_component == std::string::npos
                             ? sink_name
                             : sink_name.substr(last_component + 2);
  if ((unqualified == "memcpy" || unqualified == "memmove") && arguments.size() > 2) {
    return trim(arguments[2]);
  }
  if ((unqualified == "snprintf" || unqualified == "vsnprintf") && arguments.size() > 1) {
    return trim(arguments[1]);
  }
  return {};
}

std::optional<std::string> tracked_identifier(
  const std::string& expression,
  const SourceSinkRegistry& registry) {
  return base_identifier(trim(expression), registry);
}

ir::CandidateFinding build_candidate(
  const RuleSpec& rule,
  const ir::TranslationUnit& translation_unit,
  const ir::Function& function,
  const ir::CallSite& call,
  const std::string& source_expression,
  const std::string& source_summary,
  const std::optional<std::size_t>& destination_extent,
  const std::string& bound_expression_text,
  const bool from_test_path,
  std::vector<std::string> trace_steps,
  std::vector<ir::SourceLocation> evidence_locations) {
  ir::CandidateFinding finding;
  finding.rule_id = rule.id;
  finding.rule_family = rule.family;
  finding.file = call.location.file.empty() ? translation_unit.file_path : call.location.file;
  finding.line = call.location.line;
  finding.function_name = function.qualified_name;
  finding.sink_name = call.callee;
  finding.sink_arguments = call.argument_texts;
  finding.source_expression = source_expression;
  finding.source_summary = source_summary;
  finding.sink_summary = call.callee + "(" + join_arguments(call.argument_texts) + ")";
  finding.trace_steps = std::move(trace_steps);
  finding.provisional_severity = rule.severity;
  finding.evidence_locations = std::move(evidence_locations);
  finding.positive_conditions = rule.positive_conditions;
  finding.negative_conditions = rule.negative_conditions;
  finding.ambiguous_conditions = rule.ambiguous_conditions;
  finding.destination_extent = destination_extent;
  finding.bound_expression = bound_expression_text;
  finding.from_test_path = from_test_path;
  finding.id = "cand_" + hex_id(fnv1a64(
    finding.rule_id + "|" + finding.file + "|" + std::to_string(finding.line) + "|" + finding.sink_summary));
  return finding;
}

}  // namespace

CandidateDetector::CandidateDetector(
  const RuleRegistry& rules,
  const SourceSinkRegistry& registry)
    : rules_(rules),
      registry_(registry) {}

ir::CandidateScanResult CandidateDetector::detect(const ir::FactDatabase& facts) const {
  ir::CandidateScanResult result;
  result.compilation_database_path = facts.compilation_database_path;

  std::unordered_set<std::string> seen_ids;

  for (const auto& translation_unit : facts.translation_units) {
    const auto is_test_path = registry_.is_test_path(translation_unit.file_path);
    for (const auto& function : translation_unit.functions) {
      for (const auto& call : function.call_sites) {
        const auto family = sink_family(registry_, call.callee);
        if (!family) {
          continue;
        }

        const auto rule = rules_.rule_for_family(*family);
        if (!rule) {
          continue;
        }

        const auto source_index =
          source_argument_index(*family, call.callee, call.argument_texts);
        const auto source_expression =
          source_index < call.argument_texts.size() ? call.argument_texts[source_index] : std::string{};

        std::unordered_set<std::string> visited_variables;
        auto resolution = resolve_expression(function, source_expression, registry_, visited_variables);

        std::vector<std::string> trace_steps;
        trace_steps.push_back(
          "candidate only: configured sink " + call.callee + " matched rule family " + *family);
        if (is_test_path) {
          append_trace(trace_steps, "file path matches configured test marker");
        }
        for (const auto& step : resolution.trace_steps) {
          append_trace(trace_steps, step);
        }

        std::vector<ir::SourceLocation> evidence_locations;
        append_location(evidence_locations, call.location);
        for (const auto& location : resolution.evidence_locations) {
          append_location(evidence_locations, location);
        }

        if (const auto identifier = tracked_identifier(source_expression, registry_)) {
          append_related_context(
            function,
            registry_,
            *identifier,
            trace_steps,
            evidence_locations);
        }

        const auto candidate_bound_expression =
          *family == "dangerous_string" ? bound_expression(call.callee, call.argument_texts) : std::string{};
        if (*family == "dangerous_string" && !candidate_bound_expression.empty()) {
          const auto size_expression = candidate_bound_expression;
          if (!size_expression.empty()) {
            append_trace(trace_steps, "copy length expression " + size_expression);
          }
        }

        const auto destination_extent =
          *family == "dangerous_string" && !call.argument_texts.empty()
            ? destination_extent_for_argument(function, registry_, call.argument_texts.front())
            : std::nullopt;

        auto finding = build_candidate(
          *rule,
          translation_unit,
          function,
          call,
          source_expression,
          resolution.summary,
          destination_extent,
          candidate_bound_expression,
          is_test_path,
          std::move(trace_steps),
          std::move(evidence_locations));
        if (!seen_ids.insert(finding.id).second) {
          continue;
        }
        result.candidates.push_back(std::move(finding));
      }
    }
  }

  std::sort(
    result.candidates.begin(),
    result.candidates.end(),
    [](const ir::CandidateFinding& lhs, const ir::CandidateFinding& rhs) {
      if (lhs.file != rhs.file) {
        return lhs.file < rhs.file;
      }
      if (lhs.line != rhs.line) {
        return lhs.line < rhs.line;
      }
      return lhs.rule_id < rhs.rule_id;
    });

  return result;
}

}  // namespace sast::rules
