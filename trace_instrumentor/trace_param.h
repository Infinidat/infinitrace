/*
 * trace_param.h: A class representing a parameter passed to a trace call
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

#ifndef __TRACE_PARAM_H__
#define __TRACE_PARAM_H__

#include "clang/Rewrite/Rewriter.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/AST/AST.h"
#include "llvm/Support/raw_ostream.h"
#include "../trace_defs.h"

#include <string>
#include <iostream>

class TraceCall;
class TraceParam {
public:
    llvm::raw_ostream &Out;
    clang::DiagnosticsEngine &Diags;
    clang::ASTContext &ast;
    clang::Rewriter *Rewrite;
    std::set<const clang::Type *> &referencedTypes;
    std::set<TraceCall *> &globalTraces;

    unsigned NonInlineTraceRepresentDiag;
    unsigned MultipleReprCallsDiag;
    unsigned EmptyLiteralStringDiag;
TraceParam(
        llvm::raw_ostream &out,
        clang::DiagnosticsEngine &_Diags,
        clang::ASTContext &_ast,
        clang::Rewriter *rewriter,
        std::set<const clang::Type *> &_referencedTypes,
        std::set<TraceCall *> &global_traces);

    bool fromType(clang::QualType type, bool fill_unknown);
    bool fromExpr(const clang::Expr *E, bool deref_pointer);
    unsigned long flags;
    std::string const_str;
    std::string expression;
    std::string size_expression;
    std::string type_name;
    std::string param_name;
    TraceCall *trace_call;
    bool is_pointer;
    bool is_reference;
    bool method_generated;

    unsigned int size;
    void clear();

    TraceParam& operator = ( const TraceParam& source );
    std::string stringifyTraceParamFlags() const;
    std::string asString() const;

    bool isEnum() const {
        if (flags & TRACE_PARAM_FLAG_ENUM) {
            return true;
        } else {
            return false;
        }
    }
    bool isSimple() const {
        if ((flags & (TRACE_PARAM_FLAG_ENUM | TRACE_PARAM_FLAG_NUM_8 | TRACE_PARAM_FLAG_NUM_16 | TRACE_PARAM_FLAG_NUM_32 | TRACE_PARAM_FLAG_NUM_64)) && !(flags & TRACE_PARAM_FLAG_VARRAY)) {
            return true;
        } else {
            return false;
        }
    }

    bool isConstString() const {
        return (0 != (flags & TRACE_PARAM_FLAG_CSTR)) || !const_str.empty();
    }

    bool isZeroLength() const { return isConstString(); } // Parameter that doesn't take any space per-trace, only in the call description structure.

    bool isArray() const {
        return 0 != (flags & TRACE_PARAM_FLAG_VARRAY);
    }

    bool isRecord() const {
        return 0 != (flags & TRACE_PARAM_FLAG_RECORD);
    }

    bool isVarString() const {
        if (flags & TRACE_PARAM_FLAG_STR) {
            return true;
        } else {
            return false;
        }
    }

    bool isBuffer() const {
        if (flags & TRACE_PARAM_FLAG_VARRAY) {
            return true;
        } else {
            return false;
        }
    }

    bool isParamNameIndicator() const {
        return isConstString() &&
                (const_str.compare(0, sizeof(TRACE_PARAM_NAME_INDICATOR_PREFIX) - 1, TRACE_PARAM_NAME_INDICATOR_PREFIX) == 0);
    }

    std::string getSubsequentParamName() const;

    void setConstStr(const std::string& str) {
        flags |= TRACE_PARAM_FLAG_CSTR;
        const_str = str;
    }

    bool inferParamName();

private:
    std::string getLiteralString(const clang::Expr *expr);
    void referenceType(const clang::Type *type);
    bool parseHexBufParam(const clang::Expr *expr);
    bool parseStringParam(clang::QualType type);
    bool parseStringParam(const clang::Expr *expr);
    bool parseBasicTypeParam(clang::QualType type);
    bool parseBasicTypeParam(const clang::Expr *expr);
    bool parseRecordTypeParam(const clang::Type *expr);
    bool parseRecordTypeParam(const clang::Expr *expr);
    bool parseEnumTypeParam(clang::QualType type);
    bool parseEnumTypeParam(const clang::Expr *expr);
    bool parseClassTypeParam(const clang::Expr *expr);

    const clang::Expr *ast_expression;
};

#endif /* __TRACE_PARAM_H__ */
