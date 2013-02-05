/*
 * trace_param.cpp: A class representing a parameter passed to a trace call
 *
 *  File Created on: Feb 4, 2013 by Yitzik Casapu of Infindiat
 *  Original code by Yotam Rubin <yotamrubin@gmail.com>, 2012, Sponsored by infinidat (http://infinidat.com)
 *  Maintainer:  Yitzik Casapu of Infindiat

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */


#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <sstream>
#include <string>
#include <iostream>
#include <vector>
#include <set>

#include "../trace_user.h"
#include "../trace_str_util.h"
#include "../trace_lib.h"
#include "trace_call.h"
#include "util.h"
#include "trace_param.h"


using namespace clang;

static const Type *get_expr_type(const Expr *expr)
{
    return expr->getType().getCanonicalType().split().first;
}

TraceParam::TraceParam(
    llvm::raw_ostream &out,
    clang::DiagnosticsEngine &_Diags,
    clang::ASTContext &_ast,
    clang::Rewriter *rewriter,
    std::set<const clang::Type *> &_referencedTypes,
    std::set<TraceCall *> &global_traces):
        Out(out),
        Diags(_Diags),
        ast(_ast),
        Rewrite(rewriter),
        referencedTypes(_referencedTypes),
        globalTraces(global_traces),
        type_name("0"),
        trace_call(NULL) {
    clear();
    NonInlineTraceRepresentDiag = Diags.getCustomDiagID(clang::DiagnosticsEngine::Error,
                                                     "non inline __repr__ isn't supported");
    MultipleReprCallsDiag = Diags.getCustomDiagID(clang::DiagnosticsEngine::Error,
                                                  "a __repr__ function may only have a single call to REPR() (showing last call to REPR)");
    EmptyLiteralStringDiag = Diags.getCustomDiagID(clang::DiagnosticsEngine::Warning,
                                                  "Empty literal string in trace has no effect");

}

TraceParam& TraceParam::operator = ( const TraceParam& source )
{
    const_str        = source.const_str;
    param_name       = source.param_name;
    flags            = source.flags;
    expression       = source.expression;
    size_expression  = source.size_expression;
    size             = source.size;
    trace_call       = source.trace_call;
    Diags            = source.Diags;

    type_name = type_name;
    is_pointer = is_pointer;
    is_reference = is_reference;
    return *this;
}

std::string TraceParam::stringifyTraceParamFlags() const
{
    std::stringstream trace_flags;
    trace_flags << "0";
    if (flags & TRACE_PARAM_FLAG_NUM_8) {
        trace_flags << " | TRACE_PARAM_FLAG_NUM_8";
    }
    if (flags & TRACE_PARAM_FLAG_NUM_16) {
        trace_flags << " | TRACE_PARAM_FLAG_NUM_16";
    }
    if (flags & TRACE_PARAM_FLAG_NUM_32) {
        trace_flags << " | TRACE_PARAM_FLAG_NUM_32";
    }
    if (flags & TRACE_PARAM_FLAG_NUM_64) {
        trace_flags << " | TRACE_PARAM_FLAG_NUM_64";
    }
    if (flags & TRACE_PARAM_FLAG_VARRAY) {
        trace_flags << " | TRACE_PARAM_FLAG_VARRAY";
    }
    if (flags & TRACE_PARAM_FLAG_CSTR) {
        trace_flags << " | TRACE_PARAM_FLAG_CSTR";
    }
    if (flags & TRACE_PARAM_FLAG_STR) {
        trace_flags << " | TRACE_PARAM_FLAG_STR";
    }
    if (flags & TRACE_PARAM_FLAG_HEX) {
        trace_flags << " | TRACE_PARAM_FLAG_HEX";
    }
    if (flags & TRACE_PARAM_FLAG_UNSIGNED) {
        trace_flags << " | TRACE_PARAM_FLAG_UNSIGNED";
    }
    if (flags & TRACE_PARAM_FLAG_ZERO) {
        trace_flags << " | TRACE_PARAM_FLAG_ZERO";
    }
    if (flags & TRACE_PARAM_FLAG_ENUM) {
        trace_flags << " | TRACE_PARAM_FLAG_ENUM";
    }
    if (flags & TRACE_PARAM_FLAG_RECORD) {
        trace_flags << " | TRACE_PARAM_FLAG_RECORD";
    }
    if (flags & TRACE_PARAM_FLAG_ENTER) {
        trace_flags << " | TRACE_PARAM_FLAG_ENTER";
    }
    if (flags & TRACE_PARAM_FLAG_LEAVE) {
        trace_flags << " | TRACE_PARAM_FLAG_LEAVE";
    }

    if (flags & TRACE_PARAM_FLAG_NESTED_LOG) {
        trace_flags << " | TRACE_PARAM_FLAG_NESTED_LOG";
    }

    return trace_flags.str();
}

std::string TraceParam::asString() const
{
    std::ostringstream os;
    os << "TraceParam(flags = " << stringifyTraceParamFlags() << ", ";
    if (!const_str.empty()) {
        os << "const_str = \"" << const_str << "\", ";
    }

    if (!expression.empty()) {
        os << "expression = \"" << expression << "\", ";
    }

    os << "type_name = " << type_name << ")";
    return os.str();
}

bool TraceParam::parseBasicTypeParam(QualType qual_type)
{
    const Type *type = qual_type.split().first;


    if (type->isReferenceType() || type->isPointerType()) {
        size = ast.getTypeSize(type);
        type_name = qual_type.getAsString();

        if (type->isReferenceType()) {
            is_reference = true;
        } else {
            is_pointer = true;
        }

        flags = TRACE_PARAM_FLAG_HEX;
        if (size == 64) {
            flags |= TRACE_PARAM_FLAG_NUM_64;
        } else {
            flags |= TRACE_PARAM_FLAG_NUM_32;
        }

        size = ast.getTypeSize(type) / 8;
        return true;
    }

    if (!type->isBuiltinType()) {
        return false;
    }

    if (!type->isIntegerType()) {
        return false;
    }

    if (!type->isSignedIntegerType()) {
        flags |= TRACE_PARAM_FLAG_UNSIGNED;
    }

    switch (ast.getTypeSize(type)) {
    case 8:
        flags |= TRACE_PARAM_FLAG_NUM_8;
        break;
    case 16:
        flags |= TRACE_PARAM_FLAG_NUM_16;
        break;
    case 32:
        flags |= TRACE_PARAM_FLAG_NUM_32;
        break;
    case 64:
        flags |= TRACE_PARAM_FLAG_NUM_64;
        break;
    default:
        return false;
    }

    size = ast.getTypeSize(type) / 8;
    type_name = QualType(qual_type.split().first, 0).getAsString();
    if (type_name.compare("_Bool") == 0) {
            type_name = "bool";
    }

    return true;
}


bool TraceParam::parseBasicTypeParam(const Expr *expr)
{
    const Expr *stripped_expr = expr->IgnoreImpCasts();

    const Type *type = get_expr_type(stripped_expr);
    if (NULL == type) {
        return false;
    }

    bool parsed = parseBasicTypeParam(expr->getType().getCanonicalType());
    if (!parsed) {
        return false;
    }

    expression = getLiteralExpr(ast, Rewrite, expr);
    return true;
}

void TraceParam::referenceType(const Type *type)
{
    referencedTypes.insert(type);
}

bool TraceParam::parseRecordTypeParam(const Expr *expr)
{
  const Expr *stripped_expr = expr->IgnoreImpCasts();

  const Type *type = get_expr_type(stripped_expr);
  if (NULL == type) {
      return false;
  }

  if (!type->isRecordType()) {
      return false;
  }

  referenceType(type);
  flags |= TRACE_PARAM_FLAG_RECORD;
  expression = getLiteralExpr(ast, Rewrite, expr);
  type_name = expr->getType().getCanonicalType().getAsString();
  return true;
}


bool TraceParam::parseEnumTypeParam(QualType qual_type)
{
    if (!qual_type.split().first->isEnumeralType()) {
        return false;
    }

    referenceType(qual_type.split().first);
    flags |= TRACE_PARAM_FLAG_ENUM;
    type_name = qual_type.getAsString();
    size = 4;
    return true;
}

bool TraceParam::parseEnumTypeParam(const Expr *expr)
{
    // Enum's are implicitly cast to ints.
    const Expr *stripped_expr = expr->IgnoreImpCasts();

    const Type *type = get_expr_type(stripped_expr);
    if (NULL == type) {
        return false;
    }

    if (!parseEnumTypeParam(stripped_expr->getType().getCanonicalType().getUnqualifiedType())) {
        return false;
    }

    expression = getLiteralExpr(ast, Rewrite, expr);

    return true;
}


bool TraceParam::parseHexBufParam(const Expr *expr)
{
    const Expr *stripped_expr = expr->IgnoreParens();
    if (!isa<CStyleCastExpr>(stripped_expr)) {
        return false;
    }

    const Type *type = stripped_expr->getType().getTypePtr();
    if (!type->isPointerType()) {
        return false;
    }

    const Type *pointeeType = type->getPointeeType().IgnoreParens().getTypePtr();
    if (pointeeType->getTypeClass() != Type::VariableArray && pointeeType->getTypeClass() != Type::ConstantArray) {
        return false;
    }

    const ArrayType *A = dyn_cast<ArrayType>(pointeeType);
    if (A->getElementType().split().first->getTypeClass() != Type::Typedef) {
        return false;
    }

    const TypedefType *TDP = dyn_cast<TypedefType>(A->getElementType().split().first);
    const TypedefNameDecl *decl = TDP->getDecl();
    if (decl->getDeclName().getAsString().compare("hex_t") != 0) {
        return false;
    }

    flags |= TRACE_PARAM_FLAG_UNSIGNED | TRACE_PARAM_FLAG_VARRAY | TRACE_PARAM_FLAG_NUM_8 | TRACE_PARAM_FLAG_HEX;

    if (isa<VariableArrayType>(A)) {
        const VariableArrayType *VAT = dyn_cast<VariableArrayType>(A);
        size_expression = getLiteralExpr(ast, Rewrite, VAT->getSizeExpr());
    } else if (isa<ConstantArrayType>(A)) {
        const ConstantArrayType *CAT = dyn_cast<ConstantArrayType>(A);
        size = CAT->getSize().getZExtValue();
    }

    expression = getLiteralExpr(ast, Rewrite, expr);

    return true;
}

std::string TraceParam::getLiteralString(const Expr *expr)
{
    std::string empty_string;
    if (!isa<StringLiteral>(expr)) {
        return empty_string;
    }

    const StringLiteral *string_literal = dyn_cast<StringLiteral>(expr);
    return string_literal->getString();
}

bool TraceParam::parseStringParam(QualType qual_type)
{
    const Type *type = qual_type.split().first;
    if (!type->isPointerType()) {
        return false;
    }

    const Type *pointeeType = type->getPointeeType().split().first;
    if (!(pointeeType->isBuiltinType() && pointeeType->isCharType())) {
        return false;
    }

    type_name = qual_type.getAsString();
    return true;
}

bool TraceParam::parseStringParam(const Expr *expr)
{
    const Type *type = get_expr_type(expr);
    if (NULL == type) {
        return false;
    }
    if (!type->isPointerType()) {
        return false;
    }

    const Type *pointeeType = type->getPointeeType().split().first;
    if (!(pointeeType->isBuiltinType() && pointeeType->isCharType())) {
        return false;
    }

    const Expr *stripped_expr = expr->IgnoreImpCasts();
    if (isa<StringLiteral>(stripped_expr)) {
        std::string literalString = getLiteralString(stripped_expr);
        if (literalString.length() != 0) {
            type_name = expr->getType().getCanonicalType().getAsString();
            const_str = literalString;
            return true;
        } else {
            Diags.Report(ast.getFullLoc(stripped_expr->getLocStart()), EmptyLiteralStringDiag) << stripped_expr->getSourceRange();
            return false;
        }
    }

    std::string stringExpression = getLiteralExpr(ast, Rewrite, expr);
    if (stringExpression.length() != 0) {
        expression = stringExpression;
        flags |= TRACE_PARAM_FLAG_STR | TRACE_PARAM_FLAG_VARRAY;
        type_name = expr->getType().getCanonicalType().getAsString();
        return true;
    }

    return false;
}

bool TraceParam::fromType(QualType type, bool fill_unknown_type) {
    QualType canonical_type = type.getCanonicalType();
    if (parseEnumTypeParam(canonical_type)) {
        return true;
    } else if (parseBasicTypeParam(canonical_type)) {
        return true;
    }

    if (fill_unknown_type) {
        const_str = "...";
        return true;
    } else {
        return false;
    }
}

bool TraceParam::fromExpr(const Expr *trace_param, bool deref_pointer)
{
    if (deref_pointer && parseStringParam(trace_param)) {
        return true;
    } else if (parseHexBufParam(trace_param)) {
        return true;
    } else if (parseEnumTypeParam(trace_param)) {
        return true;
    } else if (deref_pointer && parseRecordTypeParam(trace_param)) {
        return true;
    } else if (deref_pointer && parseClassTypeParam(trace_param)) {
        return true;
    } else if (parseBasicTypeParam(trace_param)) {
        return true;
    }

    return false;
}

namespace {
class FunctionCallerFinder : public StmtVisitor<FunctionCallerFinder> {
    unsigned int call_count;
    CallExpr *CE;
    std::string function_name;
public:
    void VisitCallExpr(CallExpr* _CE)
    {
        const FunctionDecl *callee = _CE->getDirectCallee();
        if (function_name.compare(callee->getNameAsString()) == 0) {
            call_count++;
            CE = _CE;
        }
    }

    void VisitStmt(Stmt* stmt)
    {
        Stmt::child_iterator CI, CE = stmt->child_end();
        for (CI = stmt->child_begin(); CI != CE; ++CI) {
            if (*CI != 0) {
                Visit(*CI);
            }
        }
    }

    CallExpr *functionHasFunctionCall(Stmt *body, std::string _function_name, int *_call_count)
    {
        function_name = _function_name;
        CE = NULL;
        call_count = 0;
        Visit(body);
        *_call_count = call_count;
        return CE;
    }
};

}

bool TraceParam::parseClassTypeParam(const Expr *expr)
{
    const Type *type = expr->getType().getTypePtr();


    if (!type->isPointerType()) {
        return false;
    }

    const Type *pointeeType = type->getPointeeType().split().first;
    if (!pointeeType->isClassType()) {
        return false;
    }


    CXXRecordDecl *RD = cast<CXXRecordDecl>(pointeeType->getAs<RecordType>()->getDecl());
    CXXMethodDecl *MD = NULL;
    for (CXXRecordDecl::method_iterator method = RD->method_begin();
         method != RD->method_end();
         ++method) {
        if (method->getNameAsString().compare(STR(TRACE_REPR_INTERNAL_METHOD_NAME)) == 0) {
            if (!method->hasInlineBody()) {
                Diags.Report(ast.getFullLoc(method->getLocStart()), NonInlineTraceRepresentDiag) << method->getSourceRange();
                return false;
            }

            MD = *method;
            break;
        }
    }

    if (NULL == MD) {
        return false;
    }

    FunctionCallerFinder finder;
    int call_count;
    CallExpr *call_expr = finder.functionHasFunctionCall(MD->getBody(), STR(TRACE_REPR_CALL_NAME), &call_count);
    if (call_expr == NULL) {
        return false;
    }

    if (call_count > 1) {
        Diags.Report(ast.getFullLoc(call_expr->getLocStart()), MultipleReprCallsDiag) << call_expr->getSourceRange();
    }

    TraceCall *_trace_call = new TraceCall(Out, Diags, ast, Rewrite, referencedTypes, globalTraces);
    if (!_trace_call->fromCallExpr(call_expr)) {
        return false;
    }

    trace_call = _trace_call;
    // TODO: Unique name, don't add duplicate logs
    std::string _type_name = normalizeTypeName(QualType(pointeeType, 0).getAsString());
    std::stringstream trace_call_name;
    trace_call_name << _type_name;
    trace_call_name << "_tracelog";
    trace_call->trace_call_name = trace_call_name.str();
    method_generated =  true;
    flags |= TRACE_PARAM_FLAG_NESTED_LOG;
    expression = "(" + getLiteralExpr(ast, Rewrite, expr) + ")->" + STR(TRACE_REPR_INTERNAL_METHOD_NAME);
    type_name = QualType(pointeeType, 0).getAsString();

    return true;
}
