/***
Copyright 2012 Yotam Rubin <yotamrubin@gmail.com>
   Sponsored by infinidat (http://infinidat.com)
   
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
***/

#include "../trace_user.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "clang/Lex/Lexer.h"
#include "clang/Frontend/FrontendPluginRegistry.h"
#include "clang/AST/DeclVisitor.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/IdentifierTable.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/AST/AST.h"
#include "clang/AST/Attr.h"
#include "clang/Frontend/CompilerInstance.h"
#include "llvm/Support/raw_ostream.h"
#include "util.h"
#include "trace_call.h"
#include "../trace_defs.h"
#include "../trace_lib.h"

#include <sstream>
#include <string>
#include <iostream>
#include <vector>
#include <set>

using namespace clang;

static void hasReturnStmts(Stmt *S, bool &hasReturns)
{  
  for (Stmt::child_range CI = S->children(); CI; ++CI)
   if (*CI)
     hasReturnStmts(*CI, hasReturns);

 if (isa<ReturnStmt>(S))
   hasReturns = true;
 return;
}


static SourceLocation getReturnStmtEnd(ASTContext &ast, Rewriter *Rewrite, ReturnStmt *S)
{
    const Expr *retValue = S->getRetValue();
    SourceLocation startLoc;
    if (NULL != retValue) {
        startLoc = retValue->getLocStart();
    } else {
        startLoc = S->getLocStart();
    }

    SourceManager *SM = &ast.getSourceManager();
    int Size;
    if (retValue != NULL) {
        Size = Rewrite->getRangeSize(retValue->getSourceRange());
    } else {
        Size = Rewrite->getRangeSize(S->getSourceRange());
    }
    
    const char *startBuf = SM->getCharacterData(startLoc);
    const char *semiBuf = strchr(startBuf + Size, ';');
    assert((*semiBuf == ';') && "getReturnStmtEnd(): can't find ';'");
    return startLoc.getLocWithOffset(semiBuf-startBuf+1);
}



class StructFinder : public DeclVisitor<StructFinder> {
    RecordDecl *RD;
    std::string decl_name;
public:
    
    void VisitRecordDecl(RecordDecl* _RD) {
        if (_RD->isCompleteDefinition()) {
            VisitDeclContext(_RD);
            if (_RD->getDeclName().getAsString().compare(decl_name) == 0) {
                RD = _RD;
            }
        }
    }

    void VisitLinkageSpecDecl(LinkageSpecDecl *D) {
        if (D->hasBraces()) {
            VisitDeclContext(D);
        } else {
            Visit(*D->decls_begin());
        }

    }

    void VisitNamespaceDecl(NamespaceDecl *D) {
        VisitDeclContext(D);
    }

    void VisitCXXRecordDecl(CXXRecordDecl *_RD) {
        if (_RD->isCompleteDefinition()) {
            VisitDeclContext(_RD);
            if (_RD->getDeclName().getAsString().compare(decl_name) == 0) {
                RD = dyn_cast<RecordDecl>(_RD);
            }
        }
    }

    void VisitEnumDecl(EnumDecl *D) {
        if (D->isCompleteDefinition()) {
            VisitDeclContext(D);
        }
    }

    void VisitDeclContext(DeclContext *DC) {
        for (DeclContext::decl_iterator D = DC->decls_begin(), DEnd = DC->decls_end();
             D != DEnd; ++D) {
            Visit(*D);
        }
    }

    void VisitTranslationUnitDecl(TranslationUnitDecl *D) {
        VisitDeclContext(D);
    }

    RecordDecl *findDeclByName(Decl *body, std::string _decl_name) {
        decl_name = _decl_name;
        RD = NULL;
        Visit(body);
        return RD;
    }
};

static bool shouldInstrumentFunctionDecl(const FunctionDecl *D, bool whitelistExceptions)
{
    if (D->isInlined()) {
        return false;
    }
    
    const bool marked_no_instrument = D->hasAttr<clang::NoInstrumentFunctionAttr>();

    if (whitelistExceptions) {
        return marked_no_instrument;
    } else {
        return ! marked_no_instrument;
    }
}

namespace {

class DeclIterator : public RecursiveASTVisitor<DeclIterator> {
public:
    llvm::raw_ostream &Out;
    DiagnosticsEngine &Diags;
    ASTContext &ast;
    Rewriter *Rewrite;
    SourceManager *SM;
    LangOptions langOpts;
    bool whitelistExceptions;

    DeclIterator(llvm::raw_ostream& xOut, DiagnosticsEngine &_Diags, ASTContext &xAst, Rewriter *rewriter, SourceManager *sm, const LangOptions &_langOpts, std::set<const Type *> &referenced_types, std::set<TraceCall *> &global_traces, bool _whitelistExceptions) : Out(xOut), Diags(_Diags), ast(xAst), Rewrite(rewriter), SM(sm), langOpts(_langOpts), whitelistExceptions(_whitelistExceptions), referencedTypes(referenced_types), globalTraces(global_traces)  {};

    bool VisitVarDecl(VarDecl *D);
    bool VisitFunctionDecl(FunctionDecl *D);

private:
    SourceLocation getFunctionBodyStart(Stmt *FB);
    std::set<const Type *> &referencedTypes;
    std::set<TraceCall *> &globalTraces;
};

class StmtIterator : public RecursiveASTVisitor<StmtIterator> {
public:
    llvm::raw_ostream &Out;
    DiagnosticsEngine &Diags;
    ASTContext &ast;
    Rewriter *Rewrite;
    SourceManager *SM;
    LangOptions langOpts;
    Decl *D;
    bool whitelistExceptions;
    std::string enclosingClassDescriptorName;
    std::string functionName;

    StmtIterator(llvm::raw_ostream& xOut, DiagnosticsEngine &_Diags, ASTContext &xAst, Rewriter *rewriter, SourceManager *sm, const LangOptions &_langOpts, Decl *_D, bool _whitelistExceptions, std::set<const Type *>&referenced_types, std::set<TraceCall *> &global_traces) : Out(xOut), Diags(_Diags), ast(xAst), Rewrite(rewriter), SM(sm), langOpts(_langOpts), D(_D), whitelistExceptions(_whitelistExceptions), referencedTypes(referenced_types), globalTraces(global_traces)  {};

    bool VisitReturnStmt(ReturnStmt *S);
    bool VisitCallExpr(CallExpr *S);

private:
    void expandTraceLog(unsigned int severity, CallExpr *S);
    std::set<const Type *> &referencedTypes;
    std::set<TraceCall *> &globalTraces;

};


SourceLocation DeclIterator::getFunctionBodyStart(Stmt *FB)
{
    SourceLocation startLoc;
    startLoc = FB->getLocStart();
    
    return startLoc.getLocWithOffset(1);
}

bool DeclIterator::VisitFunctionDecl(FunctionDecl *D) {

	const std::string qual_name = D->getQualifiedNameAsString();
    if (NULL != strstr(qual_name.c_str(), "std::")) {
        return true;
    }
    
    CXXRecordDecl *class_decl = NULL;
    CXXMethodDecl *method_decl = NULL;
    if (isa<CXXMethodDecl>(D)) {
        method_decl = dyn_cast<CXXMethodDecl>(D);
        class_decl  = method_decl->getParent();
    }
    
    if (!(D->hasBody()  &&  D->isThisDeclarationADefinition())) {
        return true;
    }
    StmtIterator stmtiterator(Out, Diags, ast, Rewrite, SM, langOpts, D, whitelistExceptions, referencedTypes, globalTraces);
    stmtiterator.functionName = D->getNameAsString();

    bool has_returns = false;
    Stmt *const stmt = D->getBody();
    SourceLocation function_start = getFunctionBodyStart(stmt);
    TraceParam trace_param(Out, &Diags, ast, Rewrite, referencedTypes, globalTraces);
    TraceParam function_name_param(Out, &Diags, ast, Rewrite, referencedTypes, globalTraces);
    function_name_param.setConstStr(qual_name);
    TraceCall trace_call(Out, &Diags, ast, Rewrite, referencedTypes, globalTraces);
    trace_call.addTraceParam(function_name_param);
    enum trace_severity severity = TRACE_SEV_FUNC_TRACE;

    if (class_decl) {
		if (NULL != strstr(qual_name.c_str(), STR(TRACE_REPR_INTERNAL_METHOD_NAME))) {
			// This is a __repr__ call
			const QualType class_type = class_decl->getTypeForDecl()->getCanonicalTypeUnqualified();
			std::string _type_name = normalizeTypeName(class_type.getAsString());
			assert(! _type_name.empty()) ;
			std::string descriptor_name = TraceCallNameGenerator::generateTypeName(_type_name);
            std::string logid_def =
                    "const trace_log_id_t __trace_repr_logid = trace_get_descriptor_id(&" + descriptor_name + "); ";
            Rewrite->InsertText(function_start, logid_def, true);
            stmtiterator.enclosingClassDescriptorName = descriptor_name;
			goto exit;
		}

		// Avoid function traces for methods that are part of template classes.
		// TODO: Enable function traces when the arguments and return type are not templates.
		if (class_decl->isDependentType()) {
		    goto exit;
		}
    }
    
    trace_call.setSeverity(severity);
    trace_call.setKind("TRACE_LOG_DESCRIPTOR_KIND_FUNC_ENTRY");
    trace_call.initSourceLocation(&function_start);
    if (!shouldInstrumentFunctionDecl(D, whitelistExceptions)) {
        goto exit;
    }
    
    // If the function has no return statement this is our opportunity to instrument the return from it.
    hasReturnStmts(stmt, has_returns);
    if (!has_returns || D->getCallResultType()->isVoidType()) {
        SourceLocation endLocation = stmt->getLocEnd();
        TraceParam trace_param(Out, &Diags, ast, Rewrite, referencedTypes, globalTraces);
        TraceParam function_name_param(Out, &Diags, ast, Rewrite, referencedTypes, globalTraces);

        function_name_param.setConstStr(qual_name);
    
        TraceCall trace_call(Out, &Diags, ast, Rewrite, referencedTypes, globalTraces);
        enum trace_severity severity = TRACE_SEV_FUNC_TRACE;
        trace_call.setSeverity(severity);
        trace_call.setKind("TRACE_LOG_DESCRIPTOR_KIND_FUNC_LEAVE");
        trace_call.initSourceLocation(&endLocation);
        trace_call.addTraceParam(function_name_param);
        Rewrite->ReplaceText(endLocation, 1, "{if (trace_is_initialized()) {trace_decrement_nesting_level(); " + trace_call.getExpansion() + "}}}");
    }
    
    for (FunctionDecl::param_const_iterator I = D->param_begin(),
             E = D->param_end(); I != E; ++I) {
        trace_param.clear();
        if ((*I)->getNameAsString().length() == 0) {
            continue;
        }
        bool was_parsed = trace_param.fromType((*I)->getType().getCanonicalType(), true);
        if (!was_parsed) {
            stmtiterator.TraverseStmt(D->getBody());
            return true;
        }

        trace_param.param_name = (*I)->getNameAsString();
        trace_param.expression = (*I)->getNameAsString();
        trace_call.addTraceParam(trace_param);
    }


    Rewrite->InsertText(function_start, "if (trace_is_initialized()){" + trace_call.getExpansion() + "trace_increment_nesting_level();}", true);
exit:
    stmtiterator.TraverseStmt(stmt);
    stmtiterator.functionName = "";
    stmtiterator.enclosingClassDescriptorName = "";
    return true;
}

bool DeclIterator::VisitVarDecl(VarDecl *D) {
    std::string varName = D->getNameAsString();
    if (varName.compare("__traces_file_no_instrument") == 0) {
        whitelistExceptions = true;
    }
    return true;
}

static SourceRange getDeclRange(SourceManager *SM, const LangOptions *langOpts, const clang::Decl *D, bool with_semicolon)
{
    clang::SourceLocation SLoc = SM->getExpansionLoc(D->getLocStart());
	clang::SourceLocation ELoc = SM->getExpansionLoc(D->getLocEnd());
	unsigned start = SM->getFileOffset(SLoc);
	unsigned end   = SM->getFileOffset(ELoc);

	// Below code copied from clang::Lexer::MeasureTokenLength():
	clang::SourceLocation Loc = SM->getExpansionLoc(ELoc);
	std::pair<clang::FileID, unsigned> LocInfo = SM->getDecomposedLoc(Loc);
	llvm::StringRef Buffer = SM->getBufferData(LocInfo.first);
	const char *StrData = Buffer.data()+LocInfo.second;
	Lexer TheLexer(Loc, *langOpts, Buffer.begin(), StrData, Buffer.end());
	Token token;
	TheLexer.LexFromRawLexer(token);
	end += token.getLength();

    if (!with_semicolon) {
        return SourceRange(SourceLocation::getFromRawEncoding(start), SourceLocation::getFromRawEncoding(end + 2));
    }

	if (token.isNot(clang::tok::semi) && token.isNot(clang::tok::r_brace)) {
		TheLexer.LexFromRawLexer(token);
		if (token.is(clang::tok::semi)) {
			end += token.getLength();
		}
	}

	return SourceRange(SourceLocation::getFromRawEncoding(start), SourceLocation::getFromRawEncoding(end + 3));
}

bool StmtIterator::VisitReturnStmt(ReturnStmt *S)
{

    const FunctionDecl* FD = cast<FunctionDecl>(D);

    if (NULL != strstr(FD->getQualifiedNameAsString().c_str(), "std::")) {
        return true;
    }
    
    if (NULL != strstr(FD->getQualifiedNameAsString().c_str(), STR(TRACE_REPR_INTERNAL_METHOD_NAME))) {
        return true;
    }

    if (isa<CXXMethodDecl>(D)) {
        CXXMethodDecl *method_decl = dyn_cast<CXXMethodDecl>(D);
        CXXRecordDecl *class_decl = method_decl->getParent();
        if (class_decl->isDependentType()) {
            return true;
        }
    }

    if (!shouldInstrumentFunctionDecl(FD, whitelistExceptions)) {
        return true;
    }

    SourceLocation startLoc = S->getLocStart();
    SourceLocation onePastSemiLoc = getReturnStmtEnd(ast, Rewrite, S);
    
    TraceParam trace_param(Out, &Diags, ast, Rewrite, referencedTypes, globalTraces);
    TraceParam function_name_param(Out, &Diags, ast, Rewrite, referencedTypes, globalTraces);
    function_name_param.setConstStr(FD->getQualifiedNameAsString());
    
    TraceCall trace_call(Out, &Diags, ast, Rewrite, referencedTypes, globalTraces);
    enum trace_severity severity = TRACE_SEV_FUNC_TRACE;
    trace_call.setKind("TRACE_LOG_DESCRIPTOR_KIND_FUNC_LEAVE");
    trace_call.setSeverity(severity);
    trace_call.addTraceParam(function_name_param);
    trace_call.initSourceLocation(&startLoc);
    if (NULL == S->getRetValue()) {
        goto expand;
    }
    
    if (trace_param.fromExpr(S->getRetValue(), false) && !(S->getRetValue()->HasSideEffects(ast))) {
        trace_call.addTraceParam(trace_param);
    }

expand:
   std::string traceExpansion = trace_call.getExpansion();
   Rewrite->InsertText(onePastSemiLoc, "}", true);
   Rewrite->ReplaceText(startLoc, strlen("return"), "{if (current_trace_buffer != 0) {trace_decrement_nesting_level(); " + traceExpansion + "} return ");
   return true;
}

bool StmtIterator::VisitCallExpr(CallExpr *S)
{
    std::unique_ptr<TraceCall> trace_call(new TraceCall(Out, &Diags, ast, Rewrite, referencedTypes, globalTraces));
    bool successfully_parsed = trace_call->fromCallExpr(S);
    if (successfully_parsed) {
        if (trace_call->isRepr()) {
            trace_call->expandRepr();
            assert(! enclosingClassDescriptorName.empty());
            trace_call->trace_call_name = enclosingClassDescriptorName;

        } else {
        	assert(!functionName.empty());
        	trace_call->enclosing_function_name = functionName;
            trace_call->expandWithDeclaration("", true);
        }
        globalTraces.insert(trace_call.release());
    }

    return true;
}

class PreCompilationLogsConsumer : public ASTConsumer {
public:
    llvm::raw_ostream& Out;
    DiagnosticsEngine &Diags;
    raw_ostream *OutFile;
    FileID MainFileID;
    SourceManager *SM;
    std::string InFileName;
    std::stringstream type_definition;
    std::stringstream global_traces;
    CompilerInstance *compilerInstance;
    bool whitelistExceptions;
    PreCompilationLogsConsumer(StringRef inFile, raw_ostream *out, CompilerInstance &CI, bool _whitelistExceptions);

    
    std::string replaceOnce(
        std::string result, 
        const std::string& replaceWhat, 
        const std::string& replaceWithWhat)
        {
            const int pos = result.find(replaceWhat);
            if (pos==-1) return result;
            result.replace(pos,replaceWhat.size(),replaceWithWhat);
            return result;
        }
    
    std::string typeSectionName(std::string type_str) {
        return "." + replaceAll(type_str, " ", ".");
    } 

    std::string stringArrayDefinition(std::string str) {
        std::stringstream array_def;
        const char *s = str.c_str();
        array_def << "{";
        while (*s != '\0') {
            array_def << "'" << *s << "' ,";
            s++;
        }

        array_def << "'\\0' }";
        return array_def.str();
    }
    
    std::string getEnumMemberTraceDefinition(EnumDecl *ED, std::string &section_name, std::string &param_name) {
        std::stringstream enum_members;

        for (EnumDecl::enumerator_iterator
                 Enum = ED->enumerator_begin(), EnumEnd = ED->enumerator_end();
             Enum != EnumEnd; ++Enum) { 
            enum_members << "static char __attribute__((__section__(\".gnu.linkonce.type.enum" << section_name << ".data\"))) __attribute__((aligned(1)))" << param_name + Enum->getName().data() << "_str[] = " << stringArrayDefinition(Enum->getName().data()) << ";";
        }

        enum_members << "static struct trace_enum_value __attribute__((__section__(\".gnu.linkonce.type.enum" << section_name << ".data\"))) __attribute__((aligned(1)))" << param_name << "[] = {";
        for (EnumDecl::enumerator_iterator
                 Enum = ED->enumerator_begin(), EnumEnd = ED->enumerator_end();
             Enum != EnumEnd; ++Enum) {
            enum_members << "{" << param_name + Enum->getName().data() << "_str, " << Enum->getInitVal().getZExtValue() << "},";
        }

        enum_members << "{0, 0}}; ";
        return enum_members.str();
    }
    
    void declareEnumeralType(const EnumType *type) {
        EnumDecl *ED = type->getDecl();
        std::string type_str = normalizeTypeName(QualType(type, 0).getAsString());
        std::string section_name = typeSectionName(QualType(type, 0).getAsString());
        std::string type_param_var_name = type_str + "_type_params";
        std::string section_defs_attribute =  "__attribute__((__section__(\".gnu.linkonce.type.enum" + section_name + ".defs\"))) __attribute__((aligned(1)))";
        std::string section_ptr_attribute =  "__attribute__((__section__(\".gnu.linkonce.type.enum" + section_name + ".ptr\"))) __attribute__((aligned(1)))";

        std::string type_def_name = type_str + "_type_definition";
        type_definition << "extern struct trace_type_definition " << type_def_name << ";";
        type_definition << "struct trace_type_definition " << section_ptr_attribute << "* " << type_str << "_ptr = " << "&" << type_def_name << ";";
        type_definition << getEnumMemberTraceDefinition(ED, section_name, type_param_var_name);
        type_definition << "struct trace_type_definition " << section_defs_attribute  << type_str << "_type_definition = {";
        type_definition << "TRACE_TYPE_ID_ENUM, \"" <<  QualType(type, 0).getAsString() << "\", {" << type_param_var_name  << "}};";
        type_definition << "\n";
    }
        
    void mapType(const Type *type) {
        if (type->isEnumeralType()) {
            const EnumType *enum_type = type->getAs<EnumType>();
            declareEnumeralType(enum_type);
        }
    }

    void buildNullType() {
        type_definition << "void __attribute__((__section__(\".gnu.linkonce.null_type""\"))) __attribute__((aligned(1))) *null_type = 0; ";
    }
    
    void buildReferencedTypes() {
        std::set<const Type *>::iterator iter;
        for (iter = referencedTypes.begin(); iter != referencedTypes.end(); ++iter) {
            mapType(*iter);
        }

        buildNullType();
    }

    void buildGlobalTraces() {
        for (std::set<TraceCall *>::const_iterator iter = globalTraces.begin(); iter != globalTraces.end(); ++iter) {
            global_traces << (*iter)->getTraceDeclaration();
        }
    }


    void writeGlobalTraces(ASTContext &C) {
        StructFinder struct_finder;
        RecordDecl *record_struct = struct_finder.findDeclByName(C.getTranslationUnitDecl(), "trace_log_descriptor");
        assert(record_struct != NULL);

        SourceRange range = getDeclRange(SM, &C.getLangOpts(), record_struct, true);
        Rewrite.InsertText(range.getEnd(), global_traces.str());
    }
    
    void HandleTranslationUnit(ASTContext &C) {
        Rewrite.setSourceMgr(C.getSourceManager(), C.getLangOpts());
        SM = &C.getSourceManager();
        MainFileID = SM->getMainFileID();
        DeclIterator decliterator(Out, Diags, C, &Rewrite, SM, C.getLangOpts(), referencedTypes, globalTraces, whitelistExceptions);
        decliterator.TraverseDecl(C.getTranslationUnitDecl());
        buildReferencedTypes();
        buildGlobalTraces();
        if (const RewriteBuffer *RewriteBuf =
            Rewrite.getRewriteBufferFor(MainFileID)) {
            writeGlobalTraces(C);
            *OutFile << std::string(RewriteBuf->begin(), RewriteBuf->end());
            *OutFile << type_definition.str();
        } else {
            StringRef buffer = SM->getBufferData(MainFileID).data();
            *OutFile << std::string(buffer);
        }
    }

private:
    std::set<const Type *> referencedTypes;
    std::set<TraceCall *> globalTraces;
    std::set<std::string> classLogDescriptorsUsed;
    Rewriter Rewrite;
};

PreCompilationLogsConsumer::PreCompilationLogsConsumer(StringRef inFile, raw_ostream *out, CompilerInstance &CI, bool _whitelistExceptions)
    : Out(llvm::errs()), Diags(CI.getDiagnostics()), OutFile(out), InFileName(inFile), compilerInstance(&CI), whitelistExceptions(_whitelistExceptions)
{
}

class InstrumentCodeAction : public PluginASTAction {
private:
    raw_ostream *OS;
    StringRef InFile;
    CompilerInstance *CI;
    bool whitelistExceptions;
protected:
    std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI, llvm::StringRef InFile) {
        if (raw_ostream *OS = CI.createDefaultOutputFile(false, InFile, "cpp"))
            return std::unique_ptr<ASTConsumer>((ASTConsumer*)new PreCompilationLogsConsumer(InFile, OS, CI, whitelistExceptions));
        else {
            return NULL;
        }
    }

    bool ParseArgs(const CompilerInstance &CI,
                   const std::vector<std::string>& args) {
        whitelistExceptions = false;
        for (unsigned i = 0, e = args.size(); i != e; ++i) {
            if (args[i].compare("disable-function-tracing") == 0) {
                whitelistExceptions = true;
            }
        }

        return true;
    }
    
    void PrintHelp(llvm::raw_ostream& ros) {
        ros << "\n";
    }

};

static FrontendPluginRegistry::Add<InstrumentCodeAction>
X("trace-instrument", "Instrument code for traces");

} // namespace
