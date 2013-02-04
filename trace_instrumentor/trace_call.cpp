/*
 * trace_call.cpp: A class representing an individual call to the trace pseudo-functions.
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


#include "../min_max.h"
#include "../trace_str_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <sstream>

#include "util.h"
#include "trace_call.h"

using namespace clang;

static inline bool isCPlusPlus(LangOptions const& langOpts)
{
    return langOpts.CPlusPlus == 1;
}

static inline std::string castTo(LangOptions const& langOpts, const std::string& orig_expr, const std::string& cast_type)
{
     if (isCPlusPlus(langOpts)) {
         return "reinterpret_cast<" + cast_type + ">(" + orig_expr + ")";
     } else {
         return "(" + cast_type + ") (" + orig_expr + ")";
     }
 }

static inline std::string externGlobal(LangOptions const& langOpts)
{
    if (isCPlusPlus(langOpts)) {
        return "extern \"C\"";
    } else {
        return "extern";
    }
}

static bool traceCallReferenced(const std::set<TraceCall *> &traces, const std::string& trace_name)
{
    for (std::set<TraceCall *>::iterator i = traces.begin(); i != traces.end(); i++) {
        TraceCall *trace_call = *i;
        if (trace_call->trace_call_name.compare(trace_name) == 0) {
            return true;
        }
    }

    return false;
}

std::string TraceCall::getTraceDeclaration() const
{
    std::stringstream params;
    std::string flags;
    std::string str;
    std::string param_name;
    for (unsigned int i = 0; i < args.size(); i++) {
        const TraceParam &param = args[i];
        param_name = "0";
        flags = param.stringifyTraceParamFlags();
        if (param.param_name.size() > 0) {
            flags += "| TRACE_PARAM_FLAG_NAMED_PARAM";
            param_name = "\"" + param.param_name + "\"";
        }

        if (param.const_str.size() > 0) {
            flags +=  "| TRACE_PARAM_FLAG_CSTR";
            str = "{\"" + param.const_str + "\"}";
        } else {
            std::string type = "0";
            if (param.type_name.compare("0") != 0) {
                str = "{\"" + param.type_name + "\"}";
            }
        }

        params << "{" << flags << ", " << param_name << "," << str << "},";
    }

    params << "{0, 0, {0}}";
    std::stringstream descriptor;
    descriptor << "static struct trace_param_descriptor " << trace_call_name << "_params[] = {";
    descriptor << params.str() << "};";
    descriptor << "static struct trace_log_descriptor __attribute__((__section__(\".static_log_data\"))) " << trace_call_name << "= { ";
    descriptor << kind;
#if (TRACE_FORMAT_VERSION >= TRACE_FORMAT_VERSION_INTRODUCED_FILE_FUNCTION_METADATA)
    descriptor << ", __LINE__";
    descriptor << ", " << getSeverity();
#endif
    descriptor << ", " << trace_call_name << "_params" << ", ";
#if (TRACE_FORMAT_VERSION >= TRACE_FORMAT_VERSION_INTRODUCED_FILE_FUNCTION_METADATA)
    descriptor << "__FILE__, __FUNCTION__" ;
#endif
    descriptor << " };";

    return descriptor.str();
}

void TraceCall::replaceExpr(const Expr *expr, std::string replacement)
{
    SourceRange source_range = expr->getSourceRange();
    unsigned int size = Rewrite->getRangeSize(source_range);

    Rewrite->ReplaceText(expr->getLocStart(), size, replacement);
}


const char *sev_to_str[] = {"INVALID", "FUNC_TRACE",

#define TRACE_SEV_X(ignored, sev) #sev,

        TRACE_SEVERITY_DEF

#undef TRACE_SEV_X

};

std::string TraceCall::getSeverity() const
{
    return "TRACE_SEV_" + std::string(sev_to_str[severity]);
}

std::string TraceCall::commitRecords() const
{
    std::stringstream code;
    code << "trace_commit_records(__records, __rec_idx + 1, " << getSeverityExpr() << "); ";
    code << "trace_internal_err_record_if_necessary(__trace_saved_errno, __records); ";
    return code.str();
}

std::string TraceCall::getSeverityExpr() const
{
    assert(!isRepr());
    assert(severity > TRACE_SEV_INVALID);
    return getSeverity();
}

const std::string& TraceCall::getPayloadExpr()
{
    static const std::string payload_expr("__records[__rec_idx].u.payload");
    return payload_expr;
}

std::string TraceCall::varlength_initializeTypedRecord() const
{
    return initializeOpeningTypedRecord(".");
}

std::string TraceCall::constlength_initializeTypedRecord(unsigned int& buf_left) const
{
    std::stringstream code;
    code << initializeOpeningTypedRecord(".");
    buf_left = TRACE_RECORD_PAYLOAD_SIZE - sizeof(static_cast<struct trace_record *>(NULL)->u.typed.log_id);
    return code.str();
}

std::string TraceCall::initializeOpeningTypedRecord(const std::string& deref_operator) const
{
    std::stringstream code;
    const std::string rec_expr("__records[__rec_idx]");

    code << rec_expr << deref_operator << "u.typed.log_id = &tracelog - __static_log_information_start;";
    return code.str();
}

std::string TraceCall::initializeIntermediateTypedRecord(const std::string& deref_operator) const
{
    std::stringstream code;
    const std::string rec_expr("__records[__rec_idx]");

    code << rec_expr << deref_operator << "u.typed.log_id = -1U;";
    return code.str();
}

std::string TraceCall::constlength_goToNextRecord(unsigned int& buf_left) const {
    std::stringstream code;
    code << advanceRecordArrayIdx();
    buf_left = TRACE_RECORD_PAYLOAD_SIZE;
    return code.str();
}

std::string TraceCall::varlength_goToNextRecord() const {
    std::stringstream code;
    code << advanceRecordArrayIdx();
    code << "__typed_buf = " << getPayloadExpr() << ";";
    return code.str();
}

std::string TraceCall::genMIN(const std::string &a, const std::string &b)
{
    std::stringstream code;
    code << "((" << a << ")<(" << b << ") ? (" << a << "):(" << b << "))";
    return code.str();
}

std::string TraceCall::varlength_getTraceWriteExpression() const
{
    std::stringstream start_record;
    bool varlength_encountered = isRepr();
    unsigned buf_left = TRACE_RECORD_PAYLOAD_SIZE - 4;

     for (unsigned int i = 0; i < args.size(); i++) {
        const TraceParam &param = args[i];

        if (param.isSimple()) {
            if (varlength_encountered) {
                start_record << varlength_writeSimpleValue(param.expression, param.type_name, param.is_pointer, param.is_reference);
            }
            else {
                start_record << constlength_writeSimpleValue(param.expression, param.type_name, param.is_pointer, param.is_reference, param.size, buf_left);
            }
        }
        else {
            if (! varlength_encountered) {
                varlength_encountered = true;
                start_record << "__typed_buf = " << getPayloadExpr() << " + "  << TRACE_RECORD_PAYLOAD_SIZE - buf_left << "; ";
            }

            if (param.isVarString()) {
                start_record << "__typed_buf = trace_copy_vstr_to_records(&__records, &__rec_idx, &__records_array_len, __typed_buf, ";
                start_record << castTo(ast.getLangOptions(), param.expression, "const char *");
                start_record << "); ";
            }

            else if (param.trace_call) {
                // TODO: Need to check why we are calling traceCallReferenced(), and why it's doing a linear search.
                // The whole point about using a set is that the item is only inserted if it's not there already.
                if (!traceCallReferenced(globalTraces, param.trace_call->trace_call_name)) {
                    globalTraces.insert(param.trace_call);
                }

                // TODO: Just do a single copy
                std::string logid = "(&" + param.trace_call->trace_call_name + "- __static_log_information_start)";
                std::string _type_name = "int";
                start_record << varlength_writeSimpleValue(logid, _type_name, false, false);

                start_record << param.expression;
                start_record << "(__typed_buf, __records, __rec_idx, __records_array_len); ";
            }

            else {
                // TODO: Handle variable length arrays and records, which are currently ignored.
                assert (param.isConstString() || param.isArray() || param.isRecord());
            }
        }
     }

     assert (varlength_encountered);

     start_record << "trace_clear_record_remainder(__records, __rec_idx, __typed_buf); ";
     return start_record.str();
}

std::string TraceCall::allocRecordArray() const
{
    std::stringstream code;

    code << "const int __trace_saved_errno = trace_internal_err_clear_errno(); ";
    code << "unsigned __records_array_len = p_trace_runtime_control->initial_records_per_trace; ";
    code << "struct trace_record __records_initial_array[__records_array_len]; ";
    code << "struct trace_record* __records = __records_initial_array; ";
    code << "unsigned __rec_idx = 0; ";

    return code.str();
}

std::string TraceCall::advanceRecordArrayIdx() const
{
    return "trace_advance_record_array(&__records, &__rec_idx, &__records_array_len); ";
}

std::string TraceCall::writeSimpleValueSrcDecl(const std::string &expression, const std::string &type_name, bool is_pointer, bool is_reference) const
{
    std::string src_type;
    std::string src_init_expr;
    const std::string ptr_type("volatile const void *");

    if (is_pointer || is_reference) {
        src_type = ptr_type;
        std::string to_ptr(is_reference ? "&" : "");
        src_init_expr = castTo(ast.getLangOptions(), to_ptr + expression, ptr_type);
    }
    else {
        src_type = type_name;
        src_init_expr = "(" + expression + ")";
    }

    std::stringstream union_init_expr;
    union_init_expr << "union { ";
    union_init_expr << src_type << " v; ";
    union_init_expr << "unsigned char a[sizeof(" << src_type << ")]; ";
    union_init_expr << "} const __src__ = { " << src_init_expr << " }; ";

    return union_init_expr.str();
}

std::string TraceCall::varlength_getFullTraceWriteExpression() const
{
    std::stringstream alloc_record;
    alloc_record << allocRecordArray();
    alloc_record << "unsigned char *__typed_buf = " << getPayloadExpr() << " + " << sizeof(static_cast<struct trace_record *>(NULL)->u.typed.log_id)  << "; ";
    std::stringstream start_record;
    start_record << varlength_initializeTypedRecord();
    start_record << varlength_getTraceWriteExpression();

    return alloc_record.str() + start_record.str() + commitRecords();
}

std::string TraceCall::constlength_getFullTraceWriteExpression() const
{
    std::stringstream start_record;
    unsigned int buf_left = 0;

    start_record << constlength_initializeTypedRecord(buf_left);
    start_record << constlength_getTraceWriteExpression(buf_left);

    return allocRecordArray() + start_record.str() + commitRecords();
}

std::string TraceCall::constlength__writeSimpleValueCopyTargetExpr(unsigned buf_left) const
{
    std::stringstream serialized;
    serialized << "(" << getPayloadExpr();
    assert(buf_left <= TRACE_RECORD_PAYLOAD_SIZE);
    const unsigned idx = TRACE_RECORD_PAYLOAD_SIZE - buf_left;
    if (idx > 0) {
        serialized << " + " << idx;
    }
    serialized << ")";
    return serialized.str();
}

std::string TraceCall::constlength_writeSimpleValue(const std::string &expression, const std::string &type_name, bool is_pointer, bool is_reference, unsigned int value_size, unsigned int& buf_left) const
{
    std::stringstream serialized;

    serialized << "{ ";
    serialized << writeSimpleValueSrcDecl(expression, type_name, is_pointer, is_reference);

    unsigned int copy_size = MIN(value_size, buf_left);
    serialized << "__builtin_memcpy((" << constlength__writeSimpleValueCopyTargetExpr(buf_left) << "), __src__.a," << copy_size << ");";
    buf_left -= copy_size;

    const unsigned remaining_bytes = value_size - copy_size;
    if ((buf_left == 0) && (remaining_bytes > 0)) {
        serialized << constlength_goToNextRecord(buf_left);
        serialized << "__builtin_memcpy(" << constlength__writeSimpleValueCopyTargetExpr() << ", __src__.a + " << copy_size << ", " << remaining_bytes << ");";
        buf_left -= remaining_bytes;
    }

    serialized << "}";
    return serialized.str();
}

std::string TraceCall::varlength_writeSimpleValue(const std::string &expression, const std::string &type_name, bool is_pointer, bool is_reference) const
{
    std::stringstream serialized;
    serialized << "{ ";
    serialized << writeSimpleValueSrcDecl(expression, type_name, is_pointer, is_reference);
    serialized << "__typed_buf = trace_copy_scalar_to_records(&__records, &__rec_idx, &__records_array_len, __typed_buf, __src__.a, sizeof(__src__.a)); ";
    serialized << "} ";

    return serialized.str();
}

std::string TraceCall::constlength_getTraceWriteExpression(unsigned int& buf_left) const
{
    std::stringstream start_record;
    for (unsigned int i = 0; i < args.size(); i++) {
        const TraceParam &param = args[i];

        if (param.isSimple()) {
            start_record << constlength_writeSimpleValue(param.expression, param.type_name, param.is_pointer, param.is_reference, param.size, buf_left);
        }

        // TODO: Non "Simple" arguments can still be passed here (e.g. records), and they would likely be ignored. This should be revised!
    }

    if (buf_left > 0) {
        start_record << "__builtin_memset(" << constlength__writeSimpleValueCopyTargetExpr(buf_left) << ", 0xa5, " << buf_left << "); ";
    }

    return start_record.str();
}

std::string TraceCall::getExpansion() const {
    return getTraceDeclaration() + getFullTraceWriteExpression();
}

std::string TraceCall::getFullTraceWriteExpression() const
{
    return constantSizeTrace() ? constlength_getFullTraceWriteExpression() : varlength_getFullTraceWriteExpression();
}

/* Expand a regular trace call */
void TraceCall::expand()
{
    std::string declaration = getTraceDeclaration();
    std::string trace_write_expression = getFullTraceWriteExpression();
    static const char sev_threshold_expr[] = "((TRACE_SEV_INVALID != trace_thread_severity_threshold) ? trace_thread_severity_threshold : trace_runtime_control_get_default_min_sev())";
    replaceExpr(call_expr, "{" + declaration + "if ((" +
        getSeverity() +  ">= " + sev_threshold_expr + ") && (current_trace_buffer != 0)){"  + trace_write_expression + "}}");
}

/* Expand a recursive trace call via REPR */
void TraceCall::expandWithoutDeclaration()
{
    std::string trace_write_expression = varlength_getTraceWriteExpression();
    replaceExpr(call_expr, "if (current_trace_buffer != 0){"  + trace_write_expression + "}");
}


void TraceCall::unknownTraceParam(const Expr *trace_param) const
{
    Diags.Report(ast.getFullLoc(trace_param->getLocStart()), UnknownTraceParamDiag) << trace_param->getSourceRange();
}

enum trace_severity TraceCall::functionNameToTraceSeverity(std::string function_name)
{
    return trace_function_name_to_severity(function_name.c_str());
}

static bool valid_param_name(std::string &name)
{
    const char *ptr = name.c_str();
    if (isdigit(*ptr) || ispunct(*ptr)) {
        return false;
    }

    while (*ptr) {
        char c = *ptr;
        if (!isalnum(c) && c != '_') {
            return false;
        }
        ptr++;
    }

    return true;
}

bool TraceCall::constantSizeTrace(void) const
{
    for (unsigned int i = 0; i < args.size(); i++) {
        const TraceParam &param = args[i];
        if (param.isVarString()) {
            return false;
        }

        if (param.trace_call) {
            return false;
        }
    }

    return true;
}

bool TraceCall::parseTraceParams(CallExpr *S, std::vector<TraceParam> &args)
{
    Expr **call_args = S->getArgs();
    for (unsigned int i = 0; i < S->getNumArgs(); i++) {
        TraceParam trace_param(Out, Diags, ast, Rewrite, referencedTypes, globalTraces);
        trace_param.clear();
        if (trace_param.fromExpr(call_args[i], true)) {
            if (trace_param.const_str.length() == 0 && valid_param_name(trace_param.expression)) {
                trace_param.param_name = trace_param.expression;
            }

            args.push_back(trace_param);
        } else {
            unknownTraceParam(call_args[i]);
            return false;
        }
    }

    return true;
}

bool TraceCall::fromCallExpr(CallExpr *expr) {
    args.clear();
    severity = TRACE_SEV_INVALID;
    std::string function_name = getCallExprFunctionName(expr);
    is_repr = (function_name.compare("REPR") == 0);
    enum trace_severity _severity = functionNameToTraceSeverity(function_name);
    if ((_severity < TRACE_SEV__MIN || _severity > TRACE_SEV__MAX)) {
        if (!is_repr) {
            return false;
        }
    }

    severity = _severity;
    kind = "TRACE_LOG_DESCRIPTOR_KIND_EXPLICIT";
    if(!parseTraceParams(expr, args)) {
        return false;
    }

    call_expr = expr;
    return true;
}


