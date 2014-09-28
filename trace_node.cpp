/*
 * trace_node.cpp
 *
 *  Created on: Mar 14, 2013
 *      Author: Yitzik Casapu of Infinidat
 */

#include <cassert>
#include <cstdlib>
#include <cstdio>

#include "trace_defs.h"
#include "trace_sev_display.h"
#include "parser.h"
#include "trace_node.h"

using namespace std;

template<class T>
static T get_from_data(const void *& data) {
	T value = 0;
	if (data) {
		value = *static_cast<const T*>(data);
		data = static_cast<const char *>(data) + sizeof(value);
	}
	return value;
}

TraceNode *TraceNode::fromTraceParam(const trace_parser_buffer_context *context, const struct trace_param_descriptor *param, const void *&data)
{
	const unsigned FLAG_SUBSET_MASK =
			TraceIntegerValueNode::ALL_INT_FLAGS | TRACE_PARAM_FLAG_ENUM | TRACE_PARAM_FLAG_CSTR | TRACE_PARAM_FLAG_VARRAY | TRACE_PARAM_FLAG_NESTED_LOG ;
	TraceNode *node = NULL;

	switch (param->flags & FLAG_SUBSET_MASK) {
	case TRACE_PARAM_FLAG_CSTR:
		node = new TraceParamCStrNode(param);
		break;

	case TRACE_PARAM_FLAG_VARRAY:
		node = new TraceParamVStrNode(param, data);
		break;

	case TRACE_PARAM_FLAG_NESTED_LOG:
		if (data) {
			node = new TraceEmbeddedFormatNode(context, data);
		}
		else {
			node = new TraceEmbeddedObjectDescription(param->type_name);
		}
		break;

	case TRACE_PARAM_FLAG_ENUM:
		node = new TraceParamEnumNode(context, param, data);
		break;

	default:
		if (param->flags & TraceIntegerValueNode::ALL_INT_FLAGS) {
			node = new TraceIntegerValueNode(param, data);
		}
		else {
			assert(0 != param->flags);
			node = NULL;
		}
		break;
	}

	if (node && (param->flags & TRACE_PARAM_FLAG_NAMED_PARAM)) {
		return new TraceNameValueNode(param, node);
	}

	return node;
}

const char *AtomicValueNode::outFormattedValue(struct out_fd* out, RenderingMode mode) const
{
	const char *const start = outFormattingPrefix(out, mode);
	outValue(out);
	outFormattingSuffix(out, mode);
	return start;
}

const char *AtomicValueNode::outFormattedDescription(struct out_fd* out, RenderingMode mode) const
{
	const char *const start = outFormattingPrefix(out, mode);
	outDescription(out);
	outFormattingSuffix(out, mode);
	return start;
}

const char *AtomicValueNode::outFormattedHexValue(struct out_fd* out, RenderingMode mode) const
{
	const char *const start = outFormattingPrefix(out, mode);
	outHexValue(out);
	outFormattingSuffix(out, mode);
	return start;
}

const char *AtomicValueNode::outFormattingSuffix(struct out_fd* out, RenderingMode mode) const
{
	static const char * const suffixes[] = {
		"",
		ANSI_RESET,
	};

	const char *const start = out->buf + out->i;
	SAY_S(out, suffixes[mode]);
	return start;
}

const char *AtomicValueNode::outFormattingInvalidPrefix(struct out_fd* out, RenderingMode mode) const
{
	static const char * const prefixes[] = {
		"",
		RED_B,
	};

	const char *const start = out->buf + out->i;
	SAY_S(out, prefixes[mode]);
	return start;
}

const char *AtomicValueNode::outFormattingInvalidSuffix(struct out_fd* out, RenderingMode mode) const
{
	return outFormattingSuffix(out, mode);
}

const char *SimpleValueNode::outFormattingPrefix(struct out_fd* out, RenderingMode mode) const
{
	static const char * const prefixes[] = {
		"",
		CYAN_B,
	};

	const char *const start = out->buf + out->i;
	SAY_S(out, prefixes[mode]);
	return start;
}

TraceIntegerValueNode::TraceIntegerValueNode(const struct trace_param_descriptor *param, const void *&data)
{

#define GET_INT_TYPE(T) do { 				\
	unsigned T val;								\
	m_value = get_from_data<unsigned T>(data); \
	m_size  = sizeof(val); 				\
	m_c_signed_type = #T ; 				\
} while (0)


	switch (param->flags & ALL_INT_FLAGS) {
	case TRACE_PARAM_FLAG_NUM_8:
		GET_INT_TYPE(char);
		break;

	case TRACE_PARAM_FLAG_NUM_16:
		GET_INT_TYPE(short);
		break;

	case TRACE_PARAM_FLAG_NUM_32:
		GET_INT_TYPE(int);
		break;

	case TRACE_PARAM_FLAG_NUM_64:
		GET_INT_TYPE(long long);
		break;

	default:
		assert(0);
		break;
	}

#undef GET_INT_TYPE

	m_is_unsigned = param->flags & TRACE_PARAM_FLAG_UNSIGNED;
	m_is_hex	  = param->flags & TRACE_PARAM_FLAG_HEX;
}

const char *TraceIntegerValueNode::outDescription(struct out_fd* out) const
{
	const char *const start = out->buf + out->i;
	SAY_C(out, '<');
	if (m_is_unsigned) {
		SAY_C(out, 'u');
	}

	SAY_S(out, m_c_signed_type);
	SAY_C(out, '>');
	return start;
}

const char *TraceIntegerValueNode::outHexValue(struct out_fd* out) const
{
	const char *const start = out->buf + out->i;
	if (m_size <= sizeof(int)) {
		SAY_F(out, "0x%x", static_cast<unsigned>(m_value));
	}
	else {
		SAY_F(out, "0x%llx", m_value);
	}

	return start;
}

const char *TraceIntegerValueNode::outValue(struct out_fd* out) const
{
	if (m_is_hex) {
		return outHexValue(out);
	}

	const char *const start = out->buf + out->i;
	char fmt[8];
	const char * const ll = (m_size <= sizeof(int)) ? "" : "ll";
	sprintf(fmt, "%%%s%c", ll, m_is_unsigned ? 'u' : 'd');
	if (*ll) {
		SAY_F(out, fmt, m_value);
	}
	else {
		SAY_F(out, fmt, static_cast<unsigned>(m_value));
	}

	return start;
}

TraceParamGenericStrNode::TraceParamGenericStrNode(const char *s) :
		m_p_last_char(NULL),
		m_str(s)
{}

const char *TraceParamGenericStrNode::outValue(struct out_fd* out) const
{
	const unsigned saved_i = out->i;
	SAY_S(out, m_str);
	const unsigned len = out->i - saved_i;
	if (len >= 1) {
		m_p_last_char = m_str + len - 1;
	}
	return out->buf + saved_i;
}

const char *TraceParamGenericStrNode::getLastChar() const
{
	if (! m_p_last_char) {
		unsigned len = strlen(m_str);
		if (len >= 1) {
			m_p_last_char = m_str + len - 1;
		}
	}

	return m_p_last_char;
}

TraceParamCStrNode::TraceParamCStrNode(const struct trace_param_descriptor *param) :
		TraceParamGenericStrNode((NULL == param) ? "" : param->const_str)
{}

const char *TraceParamCStrNode::outFormattingPrefix(struct out_fd* out, RenderingMode mode) const
{
	static const char * const prefixes[] = {
		"",
		ANSI_RESET,
	};

	const char *const start = out->buf + out->i;
	SAY_S(out, prefixes[mode]);
	return start;
}

const char* TraceParamEnumNode::getCorrespondingName(const struct trace_parser_buffer_context *context, const char *type_name, unsigned int value)
{
	any_t ptr ;
	m_num_value = value;
	/* Note: hashmap_get silently circumvents the const-ness of context, but we do this carefully  */
	int rc = hashmap_get(context->type_hash, type_name, &ptr);
	if (rc != MAP_OK)
		return NULL;

	m_type = any_t2p<trace_type_definition_mapped>(ptr);

	if (m_type->map == 0) {
		m_type->map = hashmap_new();
		if (0 != m_type->map) {
			for (int i = 0; NULL !=  m_type->def->enum_values[i].name; i++) {
				rc = hashmap_put_int(m_type->map,
									 m_type->def->enum_values[i].value,
									 static_cast<any_t>(m_type->def->enum_values[i].name));
				if (MAP_OK != rc) {
					break;
				}
			}
		}
		else {
			rc = MAP_OMEM;
		}

		if (MAP_OMEM == rc) {
			errno = ENOMEM;
			hashmap_free(m_type->map);
			m_type->map = 0;
		}
	}

	if (rc == MAP_OK)
		rc = hashmap_get_int(m_type->map, value, &ptr);

	if (rc != MAP_OK)
		return NULL;

	return static_cast<const char*>(ptr);
}

TraceParamEnumNode::TraceParamEnumNode(const trace_parser_buffer_context *context, const struct trace_param_descriptor *param, const void *&data) :
		TraceParamGenericStrNode(data ? getCorrespondingName(context, param->type_name, get_from_data<uint32_t>(data)) : param->type_name),
		m_value_known(NULL != data)
{}

const char *TraceParamEnumNode::outValue(struct out_fd* out) const
{
	if (m_str) {
		return TraceParamGenericStrNode::outValue(out);
	}

	const char *start = out->buf + out->i;
	SAY_F(out, "<enum %s:%d>", getEnumName(), m_num_value);
	return start;
}

const char *TraceParamEnumNode::outDescription(struct out_fd* out) const
{
	const char *start = out->buf + out->i;
	SAY_F(out, "<%s>", getEnumName());
	return start;
}

const char *TraceParamEnumNode::outFormattingPrefix(struct out_fd* out, RenderingMode mode) const
{
	if (m_value_known && (NULL == m_type)) {
		return outFormattingInvalidPrefix(out, mode);
	}

	const char *const start = out->buf + out->i;
	static const char *const prefixes[] = {
		"",
		BLUE_B,
	};

	SAY_S(out, prefixes[mode]);
	return start;
}

TraceParamNameNode::TraceParamNameNode(const struct trace_param_descriptor *param) :
		TraceParamGenericStrNode((NULL == param) ? "" : param->param_name)
{}

const char *TraceParamNameNode::outValue(struct out_fd* out) const
{
	const char *const start = TraceParamGenericStrNode::outValue(out);
	SAY_C(out, '=');
	return start;
}

const char *TraceParamNameNode::outFormattingPrefix(struct out_fd* out, RenderingMode mode) const
{
	const char *const start = out->buf + out->i;
	static const char *const prefixes[] = {
		"",
		WHITE_B,
	};

	SAY_S(out, prefixes[mode]);
	return start;
}

TraceParamVStrNode::TraceParamVStrNode(const struct trace_param_descriptor *param, const void *&data) :
		m_base(static_cast<const char *>(data))
{
	if (NULL == data) {
		return;
	}

	m_fragments.reserve(2);
	const char *cdata = static_cast<const char *>(data);
	unsigned char continuation = FALSE;
	do {
		unsigned char sl = *cdata;
		const unsigned char CONTINUATION_MASK = 0x80;
		const unsigned char LENGTH_MASK = CONTINUATION_MASK - 1;

		unsigned char len = sl & LENGTH_MASK;
		continuation =      sl & CONTINUATION_MASK;
		cdata ++;
		if (param->flags & TRACE_PARAM_FLAG_STR) {
			const str_fragment fragment = { cdata - m_base, len };
			m_fragments.push_back(fragment);
		}
		cdata += len;

	} while (continuation);
	data = cdata;
}

const char *TraceParamVStrNode::outValue(struct out_fd* out) const
{
	const char *const start = out->buf + out->i;
	SAY_C  (out, '\"');
	for (unsigned i = 0; i < m_fragments.size(); i++) {
		SAY_ESCAPED_S(out, m_base + m_fragments[i].start_offset, m_fragments[i].length);
	}
	SAY_C  (out, '\"');
	return start;
}

const char *TraceParamVStrNode::outFormattingPrefix(struct out_fd* out, RenderingMode mode) const
{
	static const char * const prefixes[] = {
		"",
		CYAN_B,
	};

	const char *const start = out->buf + out->i;
	SAY_S(out, prefixes[mode]);
	return start;
}

const char *TraceChainNode::renderNodes(renderer rnd, struct out_fd* out, RenderingMode mode) const
{
	if (m_nodes.size() > 0) {
		const char *const start = (m_nodes[0]->*rnd)(out, mode);

		for (unsigned i = 1; i < m_nodes.size(); i++) {
			if (m_nodes[i-1]->subsequentSeparator()) {
				SAY_C(out, ' ');
			}
			(m_nodes[i]->*rnd)(out, mode);
		}

		return start;
	}
	else {
		return out->buf + out->i;
	}
}

const char *TraceChainNode::outFormattedValue(struct out_fd* out, RenderingMode mode) const
{
	return renderNodes(&TraceNode::outFormattedValue, out, mode);
}

const char *TraceChainNode::outFormattedHexValue(struct out_fd* out, RenderingMode mode) const
{
	return renderNodes(&TraceNode::outFormattedHexValue, out, mode);
}

const char *TraceChainNode::outFormattedDescription(struct out_fd* out, RenderingMode mode) const
{
	return renderNodes(&TraceNode::outFormattedDescription, out, mode);
}

TraceChainNode::~TraceChainNode()
{
	while(!m_nodes.empty()) {
		TraceNode *const node = m_nodes.back();
		if (node) {
			delete node;
		}
		m_nodes.pop_back();
	}
}

TraceNameValueNode::TraceNameValueNode(const struct trace_param_descriptor *param, TraceNode *ValueNode) :
		TraceChainNode(2)
{
	m_nodes[0] = new TraceParamNameNode(param);
	m_nodes[1] = ValueNode;
}

unsigned TraceParamsByFormatNode::initDescriptor(const trace_parser_buffer_context *context, trace_log_id_t log_id)
{
	m_desc = get_log_descriptor(context, log_id);
	unsigned i = 0;
	while(m_desc->params[i].flags) {
		i++;
	}

	return i;
}

void TraceParamsByFormatNode::parseParams(const void *&data)
{
	const unsigned char *const data_start = static_cast<const unsigned char *>(data);
	unsigned p = 0;
	const struct trace_param_descriptor * param;
	for (param = m_desc->params; 0 != param->flags; param++) {
		TraceNode * const node = TraceNode::fromTraceParam(m_context, param, data) ;
		if (node) {
			m_nodes[p++] = node;
		}
	}

	assert(param - m_desc->params == static_cast<std::ptrdiff_t>(m_nodes.size()));
	m_nodes.resize(p);
	m_bytes_processed = static_cast<const unsigned char *>(data) - data_start;
}

TraceParamsByFormatNode::TraceParamsByFormatNode(const trace_parser_buffer_context *context, const struct trace_record_typed *rec) :
		TraceChainNode(initDescriptor(context, rec->log_id)),
		m_context(context)
{
	const void *data = rec->payload;
	parseParams(data);
}

TraceParamsByFormatNode::TraceParamsByFormatNode(const trace_parser_buffer_context *context, const void *&data):
				TraceChainNode(initDescriptor(context, get_from_data<trace_log_id_t>(data))),
				m_context(context)
{
	parseParams(data);
}

TraceParamsByFormatNode::TraceParamsByFormatNode(const trace_parser_buffer_context *context, unsigned log_id) :
		TraceChainNode(initDescriptor(context, log_id)),
		m_context(context)
{
	const void *data = NULL;
	parseParams(data);
	assert(NULL == data);
}

unsigned TraceParamsByFormatNode::getNumDataBytesProcessed(bool including_log_id) const
{
	return m_bytes_processed + (including_log_id ? sizeof(trace_log_id_t) : 0);
}

TraceParamsByFormatNode::~TraceParamsByFormatNode() {}


TraceEmbeddedFormatNode::TraceEmbeddedFormatNode(const trace_parser_buffer_context *context, const void *&data) :
	TraceParamsByFormatNode(context, data)
{}

namespace {

class EnclosingBrace : public TraceParamGenericStrNode {
public:
	EnclosingBrace(const char *s) : TraceParamGenericStrNode(s) {}
	VisualElementType getElementType() const { return VISUAL_EMBEDDING_MARKER; }
	const char *outFormattingPrefix(struct out_fd* out, RenderingMode mode) const;
};

const char *EnclosingBrace::outFormattingPrefix(struct out_fd* out, RenderingMode mode) const
{
	const char *const start = out->buf + out->i;
	static const char *const prefixes[] = {
		"",
		WHITE_B,
	};

	SAY_S(out, prefixes[mode]);
	return start;
}

const EnclosingBrace embedded_fmt_enclosing_braces[] = {
	EnclosingBrace("{ "),
	EnclosingBrace(" }"),
};

class TraceClassDescNode : public TraceParamGenericStrNode {
public:
	TraceClassDescNode(const char *class_name) : TraceParamGenericStrNode(class_name) {}
	VisualElementType getElementType() const { return VISUAL_OBJECT; }
	const char *outFormattingPrefix(struct out_fd* out, RenderingMode mode __attribute__((unused))) const
	{ return out->buf + out->i; }
};

}  // Anonymous namespace

const char *TraceEmbeddedFormatNode::renderNodes(renderer rnd, struct out_fd* out, RenderingMode mode) const
{
	const char *const start = embedded_fmt_enclosing_braces[0].outFormattedValue(out, mode);
	TraceParamsByFormatNode::renderNodes(rnd, out, mode);
	embedded_fmt_enclosing_braces[1].outFormattedValue(out, mode);
	return start;
}

TraceEmbeddedObjectDescription::TraceEmbeddedObjectDescription(const char *obj_name) :
		TraceChainNode(1)
{
	m_nodes[0] = new TraceClassDescNode(obj_name);
}

const char *TraceEmbeddedObjectDescription::renderNodes(renderer rnd, struct out_fd* out, RenderingMode mode) const
{
	const char *const start = embedded_fmt_enclosing_braces[0].outFormattedValue(out, mode);
	TraceChainNode::renderNodes(rnd, out, mode);
	embedded_fmt_enclosing_braces[1].outFormattedValue(out, mode);
	return start;
}
