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
#include <assert.h>
#include <sstream>

#include "clang/Basic/FileManager.h"

#include "util.h"
#include "trace_call.h"

using namespace clang;

// TraceCallNameGenerator auxiliary class implementation
std::string TraceCallNameGenerator::s_default_trace_call_name("__trace_log_meta");

bool TraceCallNameGenerator::isDefaultName(const std::string& name) { return name == s_default_trace_call_name; }

const std::string& TraceCallNameGenerator::getDefaultName() { return s_default_trace_call_name; }

std::string TraceCallNameGenerator::generateName(const char *source_file, unsigned source_line)
{
    std::stringstream name;
    name << s_default_trace_call_name;

    if (NULL != source_file) {
        const unsigned effective_line = source_line % (1U << TRACE_LOG_DESCRIPTOR_SRC_LINE_NBITS);
        name << '_' << normalizeStr(source_file) << '_' << effective_line;

        const unsigned prev_calls_in_line = m_trace_calls_line_numbers.count(effective_line);
        if (prev_calls_in_line > 0) {
            name << "_" << prev_calls_in_line;
        }

        m_trace_calls_line_numbers.insert(effective_line);
    }

    return name.str();
}

std::string TraceCallNameGenerator::generateTypeName(const std::string& type_name)
{
    return s_default_trace_call_name + "_" + type_name;
}

// TraceCallNameGenerator class implementation

TraceCallNameGenerator TraceCall::s_name_gen;

TraceCall::TraceCall(llvm::raw_ostream &out,
        clang::DiagnosticsEngine &_Diags,
        clang::ASTContext &_ast,
        clang::Rewriter *rewriter,
        std::set<const clang::Type *> &referenced_types,
        std::set<TraceCall *> &global_traces) :
            method_generated(false),
            trace_call_name(s_name_gen.getDefaultName()),
            ast(_ast),
            Diags(_Diags),
            Out(out),
            Rewrite(rewriter),
            referencedTypes(referenced_types),
            globalTraces(global_traces)
{

	UnknownTraceParamDiag = Diags.getCustomDiagID(clang::DiagnosticsEngine::Error,
												  "Unsupported trace parameter type");
	is_repr		  = false;
	call_expr 	  = NULL;
	m_source_file = NULL;
	m_source_line = 0;
}

TraceCall::~TraceCall()
{
    globalTraces.erase(this);
}

bool TraceCall::initSourceLocation(const clang::SourceLocation *src_loc)
{
	SourceLocation loc;
	if (src_loc) {
		loc = *src_loc;
	}
	else if (call_expr) {
		loc = call_expr->getLocStart();
	}

	if (loc.isValid()) {

		const SourceManager& sm(Rewrite->getSourceMgr());
		PresumedLoc presumed_loc = sm.getPresumedLoc(sm.getSpellingLoc(loc));
		if (presumed_loc.isValid()) {
			m_source_file = presumed_loc.getFilename();
			m_source_line = presumed_loc.getLine();
		}
		else {
			std::pair<FileID, unsigned> loc_info = sm.getDecomposedSpellingLoc(loc);
			m_source_line = loc_info.second;
			const FileEntry *file_ent = sm.getFileEntryForID(loc_info.first);
			m_source_file = file_ent->getName();
		}

		return isSourceLocationValid();
	}

	return false;
}

std::string TraceCall::generateTraceCallName()
{
	trace_call_name = initSourceLocation() ?
	        s_name_gen.generateName(m_source_file, m_source_line) :
	        s_name_gen.getDefaultName();
	return trace_call_name;
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
        if (! param.param_name.empty()) {
            flags += "| TRACE_PARAM_FLAG_NAMED_PARAM";
            param_name = "\"" + param.param_name + "\"";
        }

        if (! param.const_str.empty()) {
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

    params << "{0, 0, {0}}"; 	// sentinel
    std::stringstream descriptor;
    descriptor << "static struct trace_param_descriptor " << trace_call_name << "_params[] = {";
    descriptor << params.str() << "};";
    if (!isRepr()) {
        descriptor << "static ";
    }
    descriptor << "struct trace_log_descriptor __attribute__((__section__(\".static_log_data\"))) " << trace_call_name << " = { ";
    descriptor << kind;
#if (TRACE_FORMAT_VERSION >= TRACE_FORMAT_VERSION_INTRODUCED_FILE_FUNCTION_METADATA)
    descriptor << ", ";
    if (isSourceLocationValid()) {
    	descriptor  << m_source_line;
    }
    else {
    	descriptor << "__LINE__";
    }
    descriptor << ", " << getSeverity();
#endif
    descriptor << ", " << trace_call_name << "_params" << ", ";
#if (TRACE_FORMAT_VERSION >= TRACE_FORMAT_VERSION_INTRODUCED_FILE_FUNCTION_METADATA)
    if (isSourceLocationValid()) {
    	descriptor << '"' << m_source_file  << '"';
    }
    else {
    	descriptor << "__FILE__";
    }
    descriptor << " , \"" << enclosing_function_name << '"' ;
#endif
    descriptor << " };";

    return descriptor.str();
}

void TraceCall::replaceExpr(const Expr *expr, const std::string& replacement)
{
    SourceRange source_range = expr->getSourceRange();
    unsigned int size = Rewrite->getRangeSize(source_range);

    Rewrite->ReplaceText(expr->getLocStart(), size, replacement);
}


static const char *sev_to_str[] = {"INVALID", "FUNC_TRACE",

#define TRACE_SEV_X(ignored, sev) #sev,

        TRACE_SEVERITY_DEF

#undef TRACE_SEV_X

};

std::string TraceCall::getSeverity() const
{
    assert(severity >= TRACE_SEV_INVALID);
    assert(severity <= TRACE_SEV__MAX);
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

    code << rec_expr << deref_operator << "u.typed.log_id = &" << trace_call_name << " - __static_log_information_start;";
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
    unsigned buf_left = TRACE_RECORD_PAYLOAD_SIZE - sizeof(static_cast<struct trace_record *>(NULL)->u.typed.log_id);

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
        else if (param.isZeroLength()) {
            continue;
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
                start_record << param.expression;
                start_record << "(__typed_buf, __records, __rec_idx, __records_array_len); ";
            }

            else {
                // TODO: Handle variable length arrays and records, which are currently ignored.
                assert (param.isArray() || param.isRecord());
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
    alloc_record << "unsigned char *__typed_buf; ";
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
        start_record << "__builtin_memset(" << constlength__writeSimpleValueCopyTargetExpr(buf_left) << ", TRACE_UNUSED_SPACE_FILL_VALUE, " << buf_left << "); ";
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
    expandWithDeclaration(declaration, true);
}

/* Expand a recursive trace call via REPR */
void TraceCall::expandRepr()
{
	assert(isRepr());
	std::string declaration_substitute = varlength_writeSimpleValue("__trace_repr_logid", "int", false, false);
	expandWithDeclaration(declaration_substitute, false);
}

void TraceCall::expandWithDeclaration(const std::string& declaration, bool check_threshold)
{
    std::stringstream replaced;
    replaced << "if (trace_is_initialized()";
    if (check_threshold) {
		replaced << " && (" << getSeverity() <<  " >= trace_runtime_get_current_thread_effective_sev_threshold())";
	}

    std::string expr = isRepr() ? varlength_getTraceWriteExpression() : getFullTraceWriteExpression();
    replaced << ") { " << declaration << expr << " }";

    replaceExpr(call_expr, replaced.str());
}

void TraceCall::unknownTraceParam(const Expr *trace_param) const
{
    Diags.Report(ast.getFullLoc(trace_param->getLocStart()), UnknownTraceParamDiag) << trace_param->getSourceRange();
}

enum trace_severity TraceCall::functionNameToTraceSeverity(std::string function_name)
{
    return trace_function_name_to_severity(function_name.c_str());
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
    std::string next_param_name;

    for (unsigned int i = 0; i < S->getNumArgs(); i++) {
        TraceParam trace_param(Out, Diags, ast, Rewrite, referencedTypes, globalTraces);
        trace_param.clear();
        if (trace_param.fromExpr(call_args[i], true)) {
            if (trace_param.isParamNameIndicator()) {
                next_param_name = trace_param.getSubsequentParamName();
                continue;
            }

            if (! next_param_name.empty()) {
                trace_param.param_name = next_param_name;
                next_param_name.clear();
            }
            else if (trace_param.inferParamName()){
                trace_param.flags |= TRACE_PARAM_FLAG_NAME_INFERRED;
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
    is_repr = (function_name.compare(STR(TRACE_REPR_CALL_NAME)) == 0);
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
    if (!hasSpecificCallName()) {
    	generateTraceCallName();
    }
    return !trace_call_name.empty();
}


