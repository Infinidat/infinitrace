/***
   trace_call.h:  A class representing an individual call to the trace pseudo-functions.
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

/* A CLANG plug-in that allows instrumentation to be generated. */

#ifndef __TRACE_CALL_H__
#define __TRACE_CALL_H__

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
#include "../trace_defs.h"

#include <string>
#include <iostream>
#include <vector>

#include "trace_param.h"

class TraceCall {
public:
TraceCall(llvm::raw_ostream &out,
        clang::DiagnosticsEngine &_Diags,
        clang::ASTContext &_ast,
        clang::Rewriter *rewriter,
        std::set<const clang::Type *> &referenced_types,
        std::set<TraceCall *> &global_traces);

    ~TraceCall();
    bool fromCallExpr(clang::CallExpr *exp);
    bool isRepr() const { return is_repr; }
    void addTraceParam(TraceParam &param) { args.push_back(param); }
    void setSeverity(enum trace_severity _severity) { severity = _severity; }
    void setKind(const char *_kind) { kind = _kind; }
    std::string getExpansion() const;
    void expand();
    void expandRepr();
    void expandWithDeclaration(const std::string& declaration = "", bool check_threshold = true);
    std::string getTraceDeclaration() const;
    bool initSourceLocation(const clang::SourceLocation *src_loc = NULL);
    bool isSourceLocationValid() const { return NULL != m_source_file; }
    
    bool method_generated;
    std::string trace_call_name;
    std::string enclosing_function_name;
    static std::string s_default_trace_call_name;
    
private:
    clang::ASTContext &ast;
    clang::DiagnosticsEngine &Diags;
    llvm::raw_ostream &Out;
    const clang::CallExpr *call_expr;
    std::vector<TraceParam> args;
    enum trace_severity severity;
    bool is_repr;
    const char *kind;
    clang::Rewriter *Rewrite;
    const char *m_source_file;
    unsigned    m_source_line;

    unsigned UnknownTraceParamDiag;
    
    std::set<const clang::Type *> &referencedTypes;
    std::set<TraceCall *> &globalTraces;

    enum trace_severity functionNameToTraceSeverity(std::string function_name);
    bool parseTraceParams(clang::CallExpr *S, std::vector<TraceParam> &args);
    std::string getLiteralString(const clang::Expr *expr);
    void createTraceDeclaration(clang::CallExpr *S, unsigned int severity, std::vector<TraceParam> &args);
    bool prepareSingleTraceParam(const clang::Expr *trace_param, TraceParam &parsed_trace_param);
    void replaceExpr(const clang::Expr *expr, const std::string& replacement);

    std::string getSeverity() const;
    std::string getSeverityExpr() const;
    std::string getTypeDefinitionExternDeclratations();
    static const std::string& getPayloadExpr();
    static std::string genMIN(const std::string &a, const std::string &b);
    
    std::string initializeIntermediateTypedRecord(const std::string& deref_operator) const;
    std::string initializeOpeningTypedRecord(const std::string& deref_operator) const;
    std::string writeSimpleValueSrcDecl(const std::string &expression, const std::string &type_name, bool is_pointer, bool is_reference) const;

    std::string constlength__writeSimpleValueCopyTargetExpr(unsigned buf_left = TRACE_RECORD_PAYLOAD_SIZE) const;
    std::string constlength_writeSimpleValue(const std::string &expression, const std::string &type_name, bool is_pointer, bool is_reference, unsigned int size, unsigned int& buf_left) const;
    std::string constlength_goToNextRecord(unsigned int& buf_left) const;
    std::string constlength_initializeTypedRecord(unsigned int& buf_left) const;

    std::string varlength_writeSimpleValue(const std::string &expression, const std::string &type_name, bool is_pointer, bool is_reference) const;
    std::string varlength_goToNextRecord() const;
    std::string varlength_initializeTypedRecord() const;

    std::string allocRecordArray() const;
    std::string advanceRecordArrayIdx() const;
    std::string commitRecords() const;
    bool constantSizeTrace() const;
    void unknownTraceParam(const clang::Expr *trace_param) const;

    std::string generateTraceCallName();
    bool hasSpecificCallName() const { return ! (trace_call_name.empty() || trace_call_name == s_default_trace_call_name); }

    std::string getFullTraceWriteExpression() const;
    std::string constlength_getTraceWriteExpression(unsigned int& buf_left) const;
    std::string constlength_getFullTraceWriteExpression() const;
    std::string varlength_getTraceWriteExpression() const;
    std::string varlength_getFullTraceWriteExpression() const;
};

#endif
