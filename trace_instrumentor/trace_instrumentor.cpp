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

#include "clang/Rewrite/ASTConsumers.h"
#include "clang/Rewrite/Rewriter.h"
#include "clang/Lex/Lexer.h"
#include "clang/Frontend/FrontendPluginRegistry.h"
#include "clang/AST/DeclVisitor.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/IdentifierTable.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/AST/AST.h"
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
    
    if (whitelistExceptions) {
        if (D->hasAttr<NoInstrumentFunctionAttr>()) {
            return true;
        } else {
            return false;
        }
    } else {
        if (D->hasAttr<NoInstrumentFunctionAttr>()) {
            return false;
        } else {
            return true;
        }
    }
}

namespace {

class DeclIterator : public DeclVisitor<DeclIterator> {
public:
    llvm::raw_ostream &Out;
    DiagnosticsEngine &Diags;
    ASTContext &ast;
    Rewriter *Rewrite;
    SourceManager *SM;
    LangOptions langOpts;
    bool whitelistExceptions;

    DeclIterator(llvm::raw_ostream& xOut, DiagnosticsEngine &_Diags, ASTContext &xAst, Rewriter *rewriter, SourceManager *sm, const LangOptions &_langOpts, std::set<const Type *> &referenced_types, std::set<TraceCall *> &global_traces, bool _whitelistExceptions) : Out(xOut), Diags(_Diags), ast(xAst), Rewrite(rewriter), SM(sm), langOpts(_langOpts), whitelistExceptions(_whitelistExceptions), referencedTypes(referenced_types), globalTraces(global_traces)  {};
    void VisitDeclContext(DeclContext *DC, bool Indent = true);
    void VisitTranslationUnitDecl(TranslationUnitDecl *D);
    void VisitTypedefDecl(TypedefDecl *D);
    void VisitTypeAliasDecl(TypeAliasDecl *D);
    void VisitEnumDecl(EnumDecl *D);
    void VisitRecordDecl(RecordDecl *D);
    void VisitEnumConstantDecl(EnumConstantDecl *D);
    void VisitFunctionDecl(FunctionDecl *D);
    void VisitFieldDecl(FieldDecl *D);
    void VisitVarDecl(VarDecl *D);
    void VisitLabelDecl(LabelDecl *D);
    void VisitParmVarDecl(ParmVarDecl *D);
    void VisitFileScopeAsmDecl(FileScopeAsmDecl *D);
    void VisitStaticAssertDecl(StaticAssertDecl *D);
    void VisitNamespaceDecl(NamespaceDecl *D);
    void VisitUsingDirectiveDecl(UsingDirectiveDecl *D);
    void VisitNamespaceAliasDecl(NamespaceAliasDecl *D);
    void VisitCXXRecordDecl(CXXRecordDecl *D);
    void VisitLinkageSpecDecl(LinkageSpecDecl *D);
    void VisitTemplateDecl(const TemplateDecl *D);
    void VisitFunctionTemplateDecl(FunctionTemplateDecl *D);
    void VisitClassTemplateDecl(ClassTemplateDecl *D);

private:
    SourceLocation getFunctionBodyStart(Stmt *FB);
    std::set<const Type *> &referencedTypes;
    std::set<TraceCall *> &globalTraces;
};

class StmtIterator : public StmtVisitor<StmtIterator> {
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

#define STMT(Node, Base) void Visit##Node(Node *S);
#include <clang/AST/StmtNodes.inc>

    void VisitStmt(Stmt *S);
    void VisitDecl(Decl *D);
    void VisitType(QualType T);
    void VisitName(DeclarationName Name);
    void VisitNestedNameSpecifier(NestedNameSpecifier *NNS);
    void VisitTemplateName(TemplateName Name);
    void VisitTemplateArguments(const TemplateArgumentLoc *Args, unsigned NumArgs);
    void VisitTemplateArgument(const TemplateArgument &Arg);

private:
    void expandTraceLog(unsigned int severity, CallExpr *S);
    std::set<const Type *> &referencedTypes;
    std::set<TraceCall *> &globalTraces;

};


void DeclIterator::VisitDeclContext(DeclContext *DC, bool Indent) {
  for (DeclContext::decl_iterator D = DC->decls_begin(), DEnd = DC->decls_end();
       D != DEnd; ++D) {
      Visit(*D);
  }
}

void DeclIterator::VisitTranslationUnitDecl(TranslationUnitDecl *D) {
    VisitDeclContext(D, false);
}

void DeclIterator::VisitTypedefDecl(TypedefDecl *D) {
}

void DeclIterator::VisitTypeAliasDecl(TypeAliasDecl *D) {
}

void DeclIterator::VisitEnumDecl(EnumDecl *D) {
  if (D->isCompleteDefinition()) {
      VisitDeclContext(D);
  }
}

void DeclIterator::VisitRecordDecl(RecordDecl *D) {
  if (D->isCompleteDefinition()) {
      VisitDeclContext(D);
  }
}

void DeclIterator::VisitEnumConstantDecl(EnumConstantDecl *D) {
}

SourceLocation DeclIterator::getFunctionBodyStart(Stmt *FB)
{
    SourceLocation startLoc;
    startLoc = FB->getLocStart();
    
    return startLoc.getLocWithOffset(1);
}

void DeclIterator::VisitFunctionDecl(FunctionDecl *D) {

	const std::string qual_name = D->getQualifiedNameAsString();
    if (NULL != strstr(qual_name.c_str(), "std::")) {
        return;
    }
    
    CXXRecordDecl *class_decl = NULL;
    CXXMethodDecl *method_decl = NULL;
    if (isa<CXXMethodDecl>(D)) {
        method_decl = dyn_cast<CXXMethodDecl>(D);
        class_decl  = method_decl->getParent();
    }
    
    if (!(D->hasBody()  &&  D->isThisDeclarationADefinition())) {
        return;
    }
    StmtIterator stmtiterator(Out, Diags, ast, Rewrite, SM, langOpts, D, whitelistExceptions, referencedTypes, globalTraces);
    stmtiterator.functionName = D->getNameAsString();

    bool has_returns = false;
    Stmt *stmt = D->getBody();
    SourceLocation function_start = getFunctionBodyStart(stmt);
    TraceParam trace_param(Out, Diags, ast, Rewrite, referencedTypes, globalTraces);
    TraceParam function_name_param(Out, Diags, ast, Rewrite, referencedTypes, globalTraces);
    function_name_param.setConstStr(qual_name);
    TraceCall trace_call(Out, Diags, ast, Rewrite, referencedTypes, globalTraces);
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
                    "const int __trace_repr_logid = &" + descriptor_name + " - __static_log_information_start; ";
            Rewrite->InsertText(function_start, logid_def, true);
            stmtiterator.enclosingClassDescriptorName = descriptor_name;
			goto exit;
		}

		// Avoid instrumenting methods that are part of template classes.
		if (class_decl->isDependentType()) {
			return;
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
    if (!has_returns || D->getResultType()->isVoidType()) {
        SourceLocation endLocation = stmt->getLocEnd();
        TraceParam trace_param(Out, Diags, ast, Rewrite, referencedTypes, globalTraces);
        TraceParam function_name_param(Out, Diags, ast, Rewrite, referencedTypes, globalTraces);

        function_name_param.setConstStr(qual_name);
    
        TraceCall trace_call(Out, Diags, ast, Rewrite, referencedTypes, globalTraces);
        enum trace_severity severity = TRACE_SEV_FUNC_TRACE;
        trace_call.setSeverity(severity);
        trace_call.setKind("TRACE_LOG_DESCRIPTOR_KIND_FUNC_LEAVE");
        trace_call.initSourceLocation(&endLocation);
        trace_call.addTraceParam(function_name_param);
        Rewrite->ReplaceText(endLocation, 1, "{if (current_trace_buffer != 0) {trace_decrement_nesting_level(); " + trace_call.getExpansion() + "}}}");
    }
    
    for (FunctionDecl::param_const_iterator I = D->param_begin(),
             E = D->param_end(); I != E; ++I) {
        trace_param.clear();
        if ((*I)->getNameAsString().length() == 0) {
            continue;
        }
        bool was_parsed = trace_param.fromType((*I)->getType().getCanonicalType(), true);
        if (!was_parsed) {
            stmtiterator.Visit(D->getBody());
            return;
        }

        trace_param.param_name = (*I)->getNameAsString();
        trace_param.expression = (*I)->getNameAsString();
        trace_call.addTraceParam(trace_param);
    }


    Rewrite->InsertText(function_start, "if (current_trace_buffer != 0){" + trace_call.getExpansion() + "trace_increment_nesting_level();}", true);
exit:
    stmtiterator.Visit(D->getBody());
    stmtiterator.functionName = "";
    stmtiterator.enclosingClassDescriptorName = "";
}

void DeclIterator::VisitFieldDecl(FieldDecl *D) {
}

void DeclIterator::VisitLabelDecl(LabelDecl *D) {
}


void DeclIterator::VisitVarDecl(VarDecl *D) {
    std::string varName = D->getNameAsString();
    if (varName.compare("__traces_file_no_instrument") == 0) {
        whitelistExceptions = true;
    }
}

void DeclIterator::VisitParmVarDecl(ParmVarDecl *D) {
    VisitVarDecl(D);
}

void DeclIterator::VisitFileScopeAsmDecl(FileScopeAsmDecl *D) {
}

void DeclIterator::VisitStaticAssertDecl(StaticAssertDecl *D) {
}


//----------------------------------------------------------------------------
// C++ declarations
//----------------------------------------------------------------------------
void DeclIterator::VisitNamespaceDecl(NamespaceDecl *D) {
    VisitDeclContext(D);
}

void DeclIterator::VisitUsingDirectiveDecl(UsingDirectiveDecl *D) {
}

void DeclIterator::VisitNamespaceAliasDecl(NamespaceAliasDecl *D) {
}

void DeclIterator::VisitCXXRecordDecl(CXXRecordDecl *D) {
    VisitDeclContext(D);
}

void DeclIterator::VisitLinkageSpecDecl(LinkageSpecDecl *D) {
  if (D->hasBraces()) {
    VisitDeclContext(D);
  } else
    Visit(*D->decls_begin());
}

void DeclIterator::VisitFunctionTemplateDecl(FunctionTemplateDecl *D) {
	VisitFunctionDecl(D->getTemplatedDecl());
    return;
#if 0
    for (FunctionTemplateDecl::spec_iterator I = D->spec_begin(), E = D->spec_end();
         I != E; ++I) {
        Visit(*I);
    }

    return VisitRedeclarableTemplateDecl(D);
#endif
}

void DeclIterator::VisitClassTemplateDecl(ClassTemplateDecl *D) {

	VisitRecordDecl(D->getTemplatedDecl());
	return;
#if 0
    for (ClassTemplateDecl::spec_iterator I = D->spec_begin(), E = D->spec_end();
         I != E; ++I) {
        Visit(*I);
    }

    VisitRedeclarableTemplateDecl(D);
#endif
}

void DeclIterator::VisitTemplateDecl(const TemplateDecl *D) {
    return;
#if 0
   if (const TemplateTemplateParmDecl *TTP =
       dyn_cast<TemplateTemplateParmDecl>(D)) {
       return;
   } else {
     Visit(D->getTemplatedDecl());
   }
#endif
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

void StmtIterator::VisitStmt(Stmt *S)
{

    for (Stmt::child_range C = S->children(); C; ++C) {
        if (*C) {
            Visit(*C);
        }
    }
}

void StmtIterator::VisitDeclStmt(DeclStmt *S)
{

    VisitStmt(S);
    for (DeclStmt::decl_iterator D = S->decl_begin(), DEnd = S->decl_end();
         D != DEnd; ++D)
        VisitDecl(*D);
}

void StmtIterator::VisitNullStmt(NullStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitCompoundStmt(CompoundStmt *S)
{
    
    VisitStmt(S);
}

void StmtIterator::VisitSwitchCase(SwitchCase *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitCaseStmt(CaseStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitCXXForRangeStmt(CXXForRangeStmt *S) {
    
    VisitStmt(S);
}

void StmtIterator::VisitArrayTypeTraitExpr(ArrayTypeTraitExpr *S) {
    
    VisitStmt(S);
}

void StmtIterator::VisitAsTypeExpr(AsTypeExpr *S) {
    
    VisitStmt(S);
}

void StmtIterator::VisitAtomicExpr(AtomicExpr *S) {
    
    VisitStmt(S);
}

void StmtIterator::VisitObjCBridgedCastExpr(ObjCBridgedCastExpr *S) {
    
    VisitStmt(S);
}

void StmtIterator::VisitObjCAutoreleasePoolStmt(clang::ObjCAutoreleasePoolStmt *S) {

    VisitStmt(S);
}

void StmtIterator::VisitSEHExceptStmt(SEHExceptStmt *S) {

    VisitStmt(S);
}

void StmtIterator::VisitSEHFinallyStmt(SEHFinallyStmt *S) {

    VisitStmt(S);
}

void StmtIterator::VisitSEHTryStmt(SEHTryStmt *S) {

    VisitStmt(S);
}


void StmtIterator::VisitExpressionTraitExpr(ExpressionTraitExpr *S) {
    
    VisitStmt(S);
}

void StmtIterator::VisitGenericSelectionExpr(GenericSelectionExpr *S) {
    
    VisitStmt(S);
}

void StmtIterator::VisitMaterializeTemporaryExpr(MaterializeTemporaryExpr *S) {
    
    VisitStmt(S);
}

void StmtIterator::VisitObjCIndirectCopyRestoreExpr(ObjCIndirectCopyRestoreExpr *S) {
    
    VisitStmt(S);
}

void StmtIterator::VisitSubstNonTypeTemplateParmExpr(SubstNonTypeTemplateParmExpr *S) {

    VisitStmt(S);
}

void StmtIterator::VisitUnaryExprOrTypeTraitExpr(UnaryExprOrTypeTraitExpr *S) {

    VisitStmt(S);
}

void StmtIterator::VisitDefaultStmt(DefaultStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitLabelStmt(LabelStmt *S)
{

    VisitStmt(S);
    VisitDecl(S->getDecl());
}

void StmtIterator::VisitIfStmt(IfStmt *S)
{

    VisitStmt(S);
    VisitDecl(S->getConditionVariable());
}

void StmtIterator::VisitSwitchStmt(SwitchStmt *S)
{

    VisitStmt(S);
    VisitDecl(S->getConditionVariable());
}

void StmtIterator::VisitWhileStmt(WhileStmt *S)
{

    VisitStmt(S);
    VisitDecl(S->getConditionVariable());
}

void StmtIterator::VisitDoStmt(DoStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitForStmt(ForStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitGotoStmt(GotoStmt *S)
{

    VisitStmt(S);
    VisitDecl(S->getLabel());
}

void StmtIterator::VisitIndirectGotoStmt(IndirectGotoStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitContinueStmt(ContinueStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitBreakStmt(BreakStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitReturnStmt(ReturnStmt *S)
{

    const FunctionDecl* FD = cast<FunctionDecl>(D);

    if (NULL != strstr(FD->getQualifiedNameAsString().c_str(), "std::")) {
        return;
    }
    
    if (NULL != strstr(FD->getQualifiedNameAsString().c_str(), STR(TRACE_REPR_INTERNAL_METHOD_NAME))) {
        return;
    }

    if (isa<CXXMethodDecl>(D)) {
        CXXMethodDecl *method_decl = dyn_cast<CXXMethodDecl>(D);
        CXXRecordDecl *class_decl = method_decl->getParent();
        if (class_decl->isDependentType()) {
            return;
        }
    }

    if (!shouldInstrumentFunctionDecl(FD, whitelistExceptions)) {
        return;
    }

    SourceLocation startLoc = S->getLocStart();
    SourceLocation onePastSemiLoc = getReturnStmtEnd(ast, Rewrite, S);
    
    TraceParam trace_param(Out, Diags, ast, Rewrite, referencedTypes, globalTraces);
    TraceParam function_name_param(Out, Diags, ast, Rewrite, referencedTypes, globalTraces);
    function_name_param.setConstStr(FD->getQualifiedNameAsString());
    
    TraceCall trace_call(Out, Diags, ast, Rewrite, referencedTypes, globalTraces);
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
        VisitStmt(S);
    }

expand:
   std::string traceExpansion = trace_call.getExpansion();
   Rewrite->InsertText(onePastSemiLoc, "}", true);
   Rewrite->ReplaceText(startLoc, 6, "{if (current_trace_buffer != 0) {trace_decrement_nesting_level(); " + traceExpansion + "} return ");
   return;
}

void StmtIterator::VisitAsmStmt(AsmStmt *S)
{

    VisitStmt(S);
    VisitStringLiteral(S->getAsmString());
    for (unsigned I = 0, N = S->getNumOutputs(); I != N; ++I)
    {
        VisitStringLiteral(S->getOutputConstraintLiteral(I));
    }
    for (unsigned I = 0, N = S->getNumInputs(); I != N; ++I)
    {
        VisitStringLiteral(S->getInputConstraintLiteral(I));
    }
    for (unsigned I = 0, N = S->getNumClobbers(); I != N; ++I)
        VisitStringLiteral(S->getClobber(I));
}

void StmtIterator::VisitCXXCatchStmt(CXXCatchStmt *S)
{

    VisitStmt(S);
    VisitType(S->getCaughtType());
}

void StmtIterator::VisitCXXTryStmt(CXXTryStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitObjCForCollectionStmt(ObjCForCollectionStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitObjCAtCatchStmt(ObjCAtCatchStmt *S)
{

    VisitStmt(S);
    if (S->getCatchParamDecl())
        VisitType(S->getCatchParamDecl()->getType());
}

void StmtIterator::VisitObjCAtFinallyStmt(ObjCAtFinallyStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitObjCAtTryStmt(ObjCAtTryStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitObjCAtSynchronizedStmt(ObjCAtSynchronizedStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitObjCAtThrowStmt(ObjCAtThrowStmt *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitExpr(Expr *S)
{

    VisitStmt(S);
}

void StmtIterator::VisitDeclRefExpr(DeclRefExpr *S)
{

    VisitExpr(S);
    VisitNestedNameSpecifier(S->getQualifier());
    VisitDecl(S->getDecl());
    VisitTemplateArguments(S->getTemplateArgs(), S->getNumTemplateArgs());
}

void StmtIterator::VisitPredefinedExpr(PredefinedExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitIntegerLiteral(IntegerLiteral *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitCharacterLiteral(CharacterLiteral *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitFloatingLiteral(FloatingLiteral *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitImaginaryLiteral(ImaginaryLiteral *S)
{
    VisitExpr(S);
}

void StmtIterator::VisitStringLiteral(StringLiteral *S)
{
    VisitExpr(S);
}

void StmtIterator::VisitParenExpr(ParenExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitParenListExpr(ParenListExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitUnaryOperator(UnaryOperator *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitOffsetOfExpr(OffsetOfExpr *S)
{

    VisitType(S->getTypeSourceInfo()->getType());
    unsigned n = S->getNumComponents();
    for (unsigned i = 0; i < n; ++i)
    {
        const OffsetOfExpr::OffsetOfNode& ON = S->getComponent(i);
        switch (ON.getKind())
        {
        case OffsetOfExpr::OffsetOfNode::Array:
            // Expressions handled below.
            break;

        case OffsetOfExpr::OffsetOfNode::Field:
            VisitDecl(ON.getField());
            break;

        case OffsetOfExpr::OffsetOfNode::Identifier:
            break;

        case OffsetOfExpr::OffsetOfNode::Base:
            // These nodes are implicit, and therefore don't need profiling.
            break;
        }
    }

    VisitExpr(S);
}

// void StmtIterator::VisitSizeOfAlignOfExpr(SizeOfAlignOfExpr *S)
// {

//     VisitExpr(S);
//     if (S->isArgumentType())
//         VisitType(S->getArgumentType());
// }

void StmtIterator::VisitArraySubscriptExpr(ArraySubscriptExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitCallExpr(CallExpr *S)
{
    std::auto_ptr<TraceCall> trace_call(new TraceCall(Out, Diags, ast, Rewrite, referencedTypes, globalTraces));
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
    
    VisitExpr(S);
}

void StmtIterator::VisitMemberExpr(MemberExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getMemberDecl());
    VisitNestedNameSpecifier(S->getQualifier());
}

void StmtIterator::VisitCompoundLiteralExpr(CompoundLiteralExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitCastExpr(CastExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitImplicitCastExpr(ImplicitCastExpr *S)
{

    VisitCastExpr(S);
}

void StmtIterator::VisitExplicitCastExpr(ExplicitCastExpr *S)
{

    VisitCastExpr(S);
    VisitType(S->getTypeAsWritten());
}

void StmtIterator::VisitCStyleCastExpr(CStyleCastExpr *S)
{

    VisitExplicitCastExpr(S);
}

void StmtIterator::VisitBinaryOperator(BinaryOperator *S)
{

//    VisitExpr(S);
}

void StmtIterator::VisitCompoundAssignOperator(CompoundAssignOperator *S)
{

    VisitBinaryOperator(S);
}

void StmtIterator::VisitConditionalOperator(ConditionalOperator *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitBinaryConditionalOperator(BinaryConditionalOperator *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitAddrLabelExpr(AddrLabelExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getLabel());
}

void StmtIterator::VisitStmtExpr(StmtExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitShuffleVectorExpr(ShuffleVectorExpr *S)
{
    VisitExpr(S);
}

void StmtIterator::VisitChooseExpr(ChooseExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitGNUNullExpr(GNUNullExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitVAArgExpr(VAArgExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitInitListExpr(InitListExpr *S)
{

    if (S->getSyntacticForm())
    {
        VisitInitListExpr(S->getSyntacticForm());
        return;
    }

    VisitExpr(S);
}

void StmtIterator::VisitDesignatedInitExpr(DesignatedInitExpr *S)
{

    VisitExpr(S);
    for (DesignatedInitExpr::designators_iterator D = S->designators_begin(),
             DEnd = S->designators_end();
         D != DEnd; ++D)
    {
        if (D->isFieldDesignator())
        {
            VisitName(D->getFieldName());
            continue;
        }
    }
}

void StmtIterator::VisitImplicitValueInitExpr(ImplicitValueInitExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitExtVectorElementExpr(ExtVectorElementExpr *S)
{

    VisitExpr(S);
    VisitName(&S->getAccessor());
}

void StmtIterator::VisitBlockExpr(BlockExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getBlockDecl());
}

void StmtIterator::VisitBlockDeclRefExpr(BlockDeclRefExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getDecl());
}

void StmtIterator::VisitCXXOperatorCallExpr(CXXOperatorCallExpr *S)
{

    if (S->isTypeDependent()) {
        for (unsigned I = 0, N = S->getNumArgs(); I != N; ++I)
            Visit(S->getArg(I));
        return;
    }

    VisitCallExpr(S);
}

void StmtIterator::VisitCXXMemberCallExpr(CXXMemberCallExpr *S)
{

    VisitCallExpr(S);
}

void StmtIterator::VisitCUDAKernelCallExpr(CUDAKernelCallExpr *S)
{

    VisitCallExpr(S);
}

void StmtIterator::VisitCXXNamedCastExpr(CXXNamedCastExpr *S)
{

    VisitExplicitCastExpr(S);
}

void StmtIterator::VisitCXXStaticCastExpr(CXXStaticCastExpr *S)
{

    VisitCXXNamedCastExpr(S);
}

void StmtIterator::VisitCXXDynamicCastExpr(CXXDynamicCastExpr *S)
{

    VisitCXXNamedCastExpr(S);
}

void StmtIterator::VisitCXXReinterpretCastExpr(CXXReinterpretCastExpr *S)
{

    VisitCXXNamedCastExpr(S);
}

void StmtIterator::VisitCXXConstCastExpr(CXXConstCastExpr *S)
{

    VisitCXXNamedCastExpr(S);
}

void StmtIterator::VisitCXXBoolLiteralExpr(CXXBoolLiteralExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitCXXNullPtrLiteralExpr(CXXNullPtrLiteralExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitCXXTypeidExpr(CXXTypeidExpr *S)
{

    VisitExpr(S);
    if (S->isTypeOperand())
        VisitType(S->getTypeOperand());
}

void StmtIterator::VisitCXXUuidofExpr(CXXUuidofExpr *S)
{

    VisitExpr(S);
    if (S->isTypeOperand())
        VisitType(S->getTypeOperand());
}

void StmtIterator::VisitCXXThisExpr(CXXThisExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitCXXThrowExpr(CXXThrowExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitCXXDefaultArgExpr(CXXDefaultArgExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getParam());
}

void StmtIterator::VisitCXXBindTemporaryExpr(CXXBindTemporaryExpr *S)
{

    VisitExpr(S);
    VisitDecl(
        const_cast<CXXDestructorDecl *>(S->getTemporary()->getDestructor()));
}

void StmtIterator::VisitCXXConstructExpr(CXXConstructExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getConstructor());
}

void StmtIterator::VisitCXXFunctionalCastExpr(CXXFunctionalCastExpr *S)
{

    VisitExplicitCastExpr(S);
}

void StmtIterator::VisitCXXTemporaryObjectExpr(CXXTemporaryObjectExpr *S)
{

    VisitCXXConstructExpr(S);
}

void StmtIterator::VisitCXXScalarValueInitExpr(CXXScalarValueInitExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitCXXDeleteExpr(CXXDeleteExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getOperatorDelete());
}

void StmtIterator::VisitCXXNewExpr(CXXNewExpr *S)
{

    VisitExpr(S);
    VisitType(S->getAllocatedType());
    VisitDecl(S->getOperatorNew());
    VisitDecl(S->getOperatorDelete());
    VisitDecl(S->getConstructor());
}

void StmtIterator::VisitCXXPseudoDestructorExpr(CXXPseudoDestructorExpr *S)
{

    VisitExpr(S);
    VisitNestedNameSpecifier(S->getQualifier());
    VisitType(S->getDestroyedType());
}

void StmtIterator::VisitOverloadExpr(OverloadExpr *S)
{

    VisitExpr(S);
    VisitNestedNameSpecifier(S->getQualifier());
    VisitName(S->getName());
    if (S->hasExplicitTemplateArgs())
        VisitTemplateArguments(S->getExplicitTemplateArgs().getTemplateArgs(),
                               S->getExplicitTemplateArgs().NumTemplateArgs);
}

void
StmtIterator::VisitUnresolvedLookupExpr(UnresolvedLookupExpr *S)
{

    VisitOverloadExpr(S);
}

void StmtIterator::VisitUnaryTypeTraitExpr(UnaryTypeTraitExpr *S)
{

    VisitExpr(S);
    VisitType(S->getQueriedType());
}

void StmtIterator::VisitBinaryTypeTraitExpr(BinaryTypeTraitExpr *S)
{

    VisitExpr(S);
    VisitType(S->getLhsType());
    VisitType(S->getRhsType());
}

void
StmtIterator::VisitDependentScopeDeclRefExpr(DependentScopeDeclRefExpr *S)
{

    VisitExpr(S);
    VisitName(S->getDeclName());
    VisitNestedNameSpecifier(S->getQualifier());
    if (S->hasExplicitTemplateArgs())
        VisitTemplateArguments(S->getTemplateArgs(), S->getNumTemplateArgs());
}

void StmtIterator::VisitExprWithCleanups(ExprWithCleanups *S)
{

    VisitExpr(S);
}

void
StmtIterator::VisitCXXUnresolvedConstructExpr(CXXUnresolvedConstructExpr *S)
{

    VisitExpr(S);
    VisitType(S->getTypeAsWritten());
}

void
StmtIterator::VisitCXXDependentScopeMemberExpr(CXXDependentScopeMemberExpr *S)
{

    if (!S->isImplicitAccess())
    {
        VisitExpr(S);
    }
    VisitNestedNameSpecifier(S->getQualifier());
    VisitName(S->getMember());
    if (S->hasExplicitTemplateArgs())
        VisitTemplateArguments(S->getTemplateArgs(), S->getNumTemplateArgs());
}

void StmtIterator::VisitUnresolvedMemberExpr(UnresolvedMemberExpr *S)
{

    if (!S->isImplicitAccess())
    {
        VisitExpr(S);
    }
    VisitNestedNameSpecifier(S->getQualifier());
    VisitName(S->getMemberName());
    if (S->hasExplicitTemplateArgs())
        VisitTemplateArguments(S->getTemplateArgs(), S->getNumTemplateArgs());
}

void StmtIterator::VisitCXXNoexceptExpr(CXXNoexceptExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitPackExpansionExpr(PackExpansionExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitSizeOfPackExpr(SizeOfPackExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getPack());
}

void StmtIterator::VisitSubstNonTypeTemplateParmPackExpr(
    SubstNonTypeTemplateParmPackExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getParameterPack());
    VisitTemplateArgument(S->getArgumentPack());
}

void StmtIterator::VisitOpaqueValueExpr(OpaqueValueExpr *E)
{

    VisitExpr(E);
}

void StmtIterator::VisitObjCStringLiteral(ObjCStringLiteral *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitObjCEncodeExpr(ObjCEncodeExpr *S)
{

    VisitExpr(S);
    VisitType(S->getEncodedType());
}

void StmtIterator::VisitObjCSelectorExpr(ObjCSelectorExpr *S)
{

    VisitExpr(S);
    VisitName(S->getSelector());
}

void StmtIterator::VisitObjCProtocolExpr(ObjCProtocolExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getProtocol());
}

void StmtIterator::VisitObjCIvarRefExpr(ObjCIvarRefExpr *S)
{

    VisitExpr(S);
    VisitDecl(S->getDecl());
}

void StmtIterator::VisitObjCPropertyRefExpr(ObjCPropertyRefExpr *S)
{

    VisitExpr(S);
    if (S->isImplicitProperty())
    {
        VisitDecl(S->getImplicitPropertyGetter());
        VisitDecl(S->getImplicitPropertySetter());
    } else {
        VisitDecl(S->getExplicitProperty());
    }
    if (S->isSuperReceiver())
    {
        VisitType(S->getSuperReceiverType());
    }
}

void StmtIterator::VisitObjCMessageExpr(ObjCMessageExpr *S)
{

    VisitExpr(S);
    VisitName(S->getSelector());
    VisitDecl(S->getMethodDecl());
}

void StmtIterator::VisitObjCIsaExpr(ObjCIsaExpr *S)
{

    VisitExpr(S);
}

void StmtIterator::VisitDecl(Decl *D)
{

}

void StmtIterator::VisitType(QualType T)
{

}

void StmtIterator::VisitName(DeclarationName Name)
{

}

void StmtIterator::VisitNestedNameSpecifier(NestedNameSpecifier *NNS)
{

}

void StmtIterator::VisitTemplateName(TemplateName Name)
{

}

void StmtIterator::VisitTemplateArguments(const TemplateArgumentLoc *Args,
                                          unsigned NumArgs)
{

    for (unsigned I = 0; I != NumArgs; ++I)
        VisitTemplateArgument(Args[I].getArgument());
}

void StmtIterator::VisitTemplateArgument(const TemplateArgument &Arg)
{
    // Mostly repetitive with TemplateArgument::Profile!
    switch (Arg.getKind())
    {
    case TemplateArgument::Null:
        break;

    case TemplateArgument::Type:
        VisitType(Arg.getAsType());
        break;

    case TemplateArgument::Template:
    case TemplateArgument::TemplateExpansion:
        VisitTemplateName(Arg.getAsTemplateOrTemplatePattern());
        break;

    case TemplateArgument::Declaration:
        VisitDecl(Arg.getAsDecl());
        break;

    case TemplateArgument::Integral:
        VisitType(Arg.getIntegralType());
        break;

    case TemplateArgument::Expression:
        Visit(Arg.getAsExpr());
        break;

    case TemplateArgument::Pack:
        const TemplateArgument *Pack = Arg.pack_begin();
        for (unsigned i = 0, e = Arg.pack_size(); i != e; ++i)
            VisitTemplateArgument(Pack[i]);
        break;
    }
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

        SourceRange range = getDeclRange(SM, &C.getLangOptions(), record_struct, true);
        Rewrite.InsertText(range.getEnd(), global_traces.str());
    }
    
    void HandleTranslationUnit(ASTContext &C) {
        Rewrite.setSourceMgr(C.getSourceManager(), C.getLangOptions());
        SM = &C.getSourceManager();
        MainFileID = SM->getMainFileID();
        DeclIterator decliterator(Out, Diags, C, &Rewrite, SM, C.getLangOptions(), referencedTypes, globalTraces, whitelistExceptions);
        decliterator.Visit(C.getTranslationUnitDecl());
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
    ASTConsumer *CreateASTConsumer(CompilerInstance &CI, llvm::StringRef InFile) {
        if (raw_ostream *OS = CI.createDefaultOutputFile(false, InFile, "cpp"))
            return new PreCompilationLogsConsumer(InFile, OS, CI, whitelistExceptions);
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
