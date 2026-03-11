#include "sast/frontend_cpp/tooling_runner.hpp"

#include <algorithm>
#include <future>
#include <memory>
#include <system_error>

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Type.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendActions.h>
#include <clang/Lex/Lexer.h>
#include <clang/Tooling/CompilationDatabase.h>
#include <clang/Tooling/Tooling.h>

namespace sast::frontend_cpp {

namespace {

ir::SourceLocation to_location(
  const clang::SourceManager& source_manager,
  const clang::SourceLocation location) {
  const auto spelling = source_manager.getSpellingLoc(location);
  const auto file_id = source_manager.getFileID(spelling);
  if (const auto file_entry = source_manager.getFileEntryRefForID(file_id)) {
    auto path = file_entry->getName().str();
    if (path.empty()) {
      path = file_entry->getFileEntry().tryGetRealPathName().str();
    }
    if (!path.empty()) {
      const auto line_column = source_manager.getSpellingLineNumber(spelling);
      const auto column = source_manager.getSpellingColumnNumber(spelling);
      return {
        .file = std::move(path),
        .line = static_cast<int>(line_column),
        .column = static_cast<int>(column),
      };
    }
  }

  const auto presumed = source_manager.getPresumedLoc(spelling);
  if (!presumed.isValid()) {
    return {};
  }
  return {
    .file = presumed.getFilename(),
    .line = static_cast<int>(presumed.getLine()),
    .column = static_cast<int>(presumed.getColumn()),
  };
}

std::string source_text(
  const clang::SourceManager& source_manager,
  const clang::LangOptions& lang_options,
  const clang::SourceRange range) {
  return clang::Lexer::getSourceText(
           clang::CharSourceRange::getTokenRange(range),
           source_manager,
           lang_options)
    .str();
}

std::string callee_name(const clang::CallExpr& call) {
  if (const auto* direct = call.getDirectCallee()) {
    return direct->getQualifiedNameAsString();
  }
  return {};
}

std::optional<std::size_t> static_extent(const clang::VarDecl& decl) {
  if (const auto* constant_array = decl.getASTContext().getAsConstantArrayType(decl.getType())) {
    return static_cast<std::size_t>(constant_array->getSize().getZExtValue());
  }
  return std::nullopt;
}

std::filesystem::path canonicalize_or_empty(const std::filesystem::path& path) {
  std::error_code error;
  const auto canonical = std::filesystem::weakly_canonical(path, error);
  if (error) {
    return {};
  }
  return canonical;
}

bool has_path_prefix(
  const std::filesystem::path& path,
  const std::filesystem::path& prefix) {
  const auto canonical_path = canonicalize_or_empty(path);
  const auto canonical_prefix = canonicalize_or_empty(prefix);
  if (canonical_path.empty() || canonical_prefix.empty()) {
    return false;
  }

  auto path_iter = canonical_path.begin();
  auto prefix_iter = canonical_prefix.begin();
  for (; prefix_iter != canonical_prefix.end(); ++prefix_iter, ++path_iter) {
    if (path_iter == canonical_path.end() || *path_iter != *prefix_iter) {
      return false;
    }
  }
  return true;
}

bool is_project_location(
  const clang::SourceManager& source_manager,
  const clang::SourceLocation location,
  const std::filesystem::path& project_root) {
  if (project_root.empty()) {
    return true;
  }

  const auto normalized = to_location(source_manager, location);
  if (!normalized.valid()) {
    return false;
  }
  return has_path_prefix(normalized.file, project_root);
}

class FunctionBodyVisitor : public clang::RecursiveASTVisitor<FunctionBodyVisitor> {
 public:
  FunctionBodyVisitor(
    clang::ASTContext& context,
    ir::Function& function,
    const std::filesystem::path& project_root)
      : context_(context),
        function_(function),
        project_root_(project_root) {}

  bool VisitCallExpr(clang::CallExpr* expr) {
    if (expr == nullptr ||
        !is_project_location(context_.getSourceManager(), expr->getExprLoc(), project_root_)) {
      return true;
    }

    ir::CallSite call_site;
    call_site.callee = callee_name(*expr);
    if (call_site.callee.empty()) {
      call_site.callee = source_text(
        context_.getSourceManager(),
        context_.getLangOpts(),
        expr->getCallee()->getSourceRange());
    }
    call_site.location = to_location(context_.getSourceManager(), expr->getExprLoc());
    for (const auto* argument : expr->arguments()) {
      call_site.argument_texts.push_back(source_text(
        context_.getSourceManager(),
        context_.getLangOpts(),
        argument->getSourceRange()));
    }
    function_.call_sites.push_back(std::move(call_site));
    return true;
  }

  bool VisitDeclRefExpr(clang::DeclRefExpr* expr) {
    if (expr == nullptr ||
        !is_project_location(context_.getSourceManager(), expr->getExprLoc(), project_root_)) {
      return true;
    }
    const auto* decl = expr->getDecl();
    if (!(llvm::isa<clang::VarDecl>(decl) || llvm::isa<clang::ParmVarDecl>(decl) ||
          llvm::isa<clang::BindingDecl>(decl))) {
      return true;
    }

    ir::VariableRef reference;
    reference.name = decl->getNameAsString();
    if (llvm::isa<clang::ParmVarDecl>(decl)) {
      reference.referenced_kind = "parameter";
    } else if (llvm::isa<clang::BindingDecl>(decl)) {
      reference.referenced_kind = "binding";
    } else {
      reference.referenced_kind = "variable";
    }
    reference.location = to_location(context_.getSourceManager(), expr->getExprLoc());
    function_.variable_refs.push_back(std::move(reference));
    return true;
  }

  bool VisitVarDecl(clang::VarDecl* decl) {
    if (decl == nullptr || decl->isImplicit() || !decl->isLocalVarDecl() ||
        !is_project_location(context_.getSourceManager(), decl->getLocation(), project_root_)) {
      return true;
    }

    ir::VariableDef variable_def;
    variable_def.name = decl->getNameAsString();
    variable_def.location = to_location(context_.getSourceManager(), decl->getLocation());
    variable_def.static_extent = static_extent(*decl);
    if (const auto* initializer = decl->getInit()) {
      variable_def.initializer_text = source_text(
        context_.getSourceManager(),
        context_.getLangOpts(),
        initializer->getSourceRange());
    }
    function_.variable_defs.push_back(std::move(variable_def));
    return true;
  }

 private:
  clang::ASTContext& context_;
  ir::Function& function_;
  std::filesystem::path project_root_;
};

class TranslationUnitVisitor : public clang::RecursiveASTVisitor<TranslationUnitVisitor> {
 public:
  TranslationUnitVisitor(
    clang::ASTContext& context,
    ir::TranslationUnit& translation_unit,
    const std::filesystem::path& project_root)
      : context_(context),
        translation_unit_(translation_unit),
        project_root_(project_root) {}

  bool VisitFunctionDecl(clang::FunctionDecl* decl) {
    if (decl == nullptr || !decl->hasBody() || !decl->isThisDeclarationADefinition() ||
        !is_project_location(context_.getSourceManager(), decl->getLocation(), project_root_)) {
      return true;
    }

    ir::Function function;
    function.qualified_name = decl->getQualifiedNameAsString();
    function.return_type = decl->getReturnType().getAsString();
    function.location = to_location(context_.getSourceManager(), decl->getLocation());
    for (const auto* parameter : decl->parameters()) {
      function.parameter_names.push_back(parameter->getNameAsString());
    }

    FunctionBodyVisitor visitor(context_, function, project_root_);
    visitor.TraverseStmt(decl->getBody());
    translation_unit_.functions.push_back(std::move(function));
    return true;
  }

 private:
  clang::ASTContext& context_;
  ir::TranslationUnit& translation_unit_;
  std::filesystem::path project_root_;
};

class TranslationUnitConsumer : public clang::ASTConsumer {
 public:
  TranslationUnitConsumer(
    ir::TranslationUnit& translation_unit,
    std::filesystem::path project_root)
      : translation_unit_(translation_unit),
        project_root_(std::move(project_root)) {}

  void HandleTranslationUnit(clang::ASTContext& context) override {
    TranslationUnitVisitor visitor(context, translation_unit_, project_root_);
    visitor.TraverseDecl(context.getTranslationUnitDecl());
  }

 private:
  ir::TranslationUnit& translation_unit_;
  std::filesystem::path project_root_;
};

class TranslationUnitAction : public clang::ASTFrontendAction {
 public:
  TranslationUnitAction(
    ir::TranslationUnit& translation_unit,
    std::filesystem::path project_root)
      : translation_unit_(translation_unit),
        project_root_(std::move(project_root)) {}

  std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(
    clang::CompilerInstance& compiler,
    llvm::StringRef file) override {
    translation_unit_.file_path = file.str();
    return std::make_unique<TranslationUnitConsumer>(translation_unit_, project_root_);
  }

 private:
  ir::TranslationUnit& translation_unit_;
  std::filesystem::path project_root_;
};

class TranslationUnitActionFactory : public clang::tooling::FrontendActionFactory {
 public:
  TranslationUnitActionFactory(
    ir::TranslationUnit& translation_unit,
    std::filesystem::path project_root)
      : translation_unit_(translation_unit),
        project_root_(std::move(project_root)) {}

  std::unique_ptr<clang::FrontendAction> create() override {
    return std::make_unique<TranslationUnitAction>(translation_unit_, project_root_);
  }

 private:
  ir::TranslationUnit& translation_unit_;
  std::filesystem::path project_root_;
};

ir::TranslationUnit analyze_command(
  const build::CompileCommandInfo& command,
  const std::filesystem::path& project_root) {
  auto arguments = command.arguments;
  if (!arguments.empty()) {
    arguments.erase(arguments.begin());
  }
  arguments.erase(
    std::remove_if(
      arguments.begin(),
      arguments.end(),
      [&command](const std::string& argument) {
        std::error_code error;
        const auto path = std::filesystem::absolute(argument, error);
        return !error && std::filesystem::exists(path) &&
               std::filesystem::weakly_canonical(path) ==
                 std::filesystem::weakly_canonical(command.file);
      }),
    arguments.end());

  clang::tooling::FixedCompilationDatabase compilation_database(
    command.directory.string(),
    arguments);
  clang::tooling::ClangTool tool(compilation_database, {command.file.string()});

  ir::TranslationUnit translation_unit;
  TranslationUnitActionFactory factory(translation_unit, project_root);
  const auto exit_code = tool.run(&factory);
  if (translation_unit.file_path.empty()) {
    translation_unit.file_path = command.file.string();
  }
  if (exit_code != 0) {
    translation_unit.diagnostics.push_back(
      "LibTooling failed for " + command.file.string());
  }

  std::sort(
    translation_unit.functions.begin(),
    translation_unit.functions.end(),
    [](const ir::Function& lhs, const ir::Function& rhs) {
      return lhs.qualified_name < rhs.qualified_name;
    });
  return translation_unit;
}

}  // namespace

ir::FactDatabase ToolingRunner::analyze(
  const std::vector<build::CompileCommandInfo>& commands,
  const std::filesystem::path& compilation_database_path,
  const ToolingOptions& options) const {
  ir::FactDatabase database;
  database.compilation_database_path = std::filesystem::absolute(compilation_database_path).string();

  if (options.jobs <= 1 || commands.size() <= 1) {
    for (const auto& command : commands) {
      database.translation_units.push_back(analyze_command(command, options.project_root));
    }
  } else {
    std::vector<std::future<ir::TranslationUnit>> futures;
    futures.reserve(commands.size());
    for (const auto& command : commands) {
      futures.push_back(std::async(
        std::launch::async,
        [&command, &options]() { return analyze_command(command, options.project_root); }));
    }
    for (auto& future : futures) {
      database.translation_units.push_back(future.get());
    }
  }

  std::sort(
    database.translation_units.begin(),
    database.translation_units.end(),
    [](const ir::TranslationUnit& lhs, const ir::TranslationUnit& rhs) {
      return lhs.file_path < rhs.file_path;
    });
  return database;
}

}  // namespace sast::frontend_cpp
