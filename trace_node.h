/*
 * trace_node.h
 *
 *  Created on: Mar 14, 2013
 *      Author: Yitzik Casapu of Infinidat
 */

#ifndef TRACE_NODE_H_
#define TRACE_NODE_H_



#include <vector>
#include <stdint.h>

#include "out_fd.h"

class TraceNode {
public:
	enum VisualElementType {
		VISUAL_PARAM_NAME,
		VISUAL_SIMPLE_VALUE,
		VISUAL_CSTR,
		VISUAL_VSTR,
		VISUAL_ENUM,
		VISUAL_OBJECT,
		VISUAL_NODE_NAME,
		VISUAL_NAMED_VALUE,
		VISUAL_EMBEDDING_MARKER,
		VISUAL_ANOMALOUS,
	};

	enum RenderingMode {
		RENDER_MODE_PLAIN = 0,  // Plain text, no color
		RENDER_MODE_ANSI,   // ANSI color codes
		RENDER_MODE_COUNT,  // Keep last
	};

	// Factory Functions

	static TraceNode *fromTraceParam(const trace_parser_buffer_context *context, const struct trace_param_descriptor *param, const void *&data);

	// Functions for rendering to text
	virtual VisualElementType getElementType() const = 0;

	virtual const char *outValue(struct out_fd* out) const = 0;
	virtual const char *outHexValue(struct out_fd* out) const	 { return outValue(out); }
	virtual const char *outDescription(struct out_fd* out) const { return outValue(out); }
	virtual const char *outFormattedValue(struct out_fd* out, RenderingMode mode) const = 0;
	virtual const char *outFormattedHexValue(struct out_fd* out, RenderingMode mode) const	  { return outFormattedValue(out, mode); }
	virtual const char *outFormattedDescription(struct out_fd* out, RenderingMode mode) const { return outFormattedValue(out, mode); }
	virtual const char *outFormattingPrefix(struct out_fd* out, RenderingMode mode) const = 0;
	virtual const char *outFormattingSuffix(struct out_fd* out, RenderingMode mode) const = 0;
	virtual bool subsequentSeparator() const { return true; }
	// Make destructor virtual
	virtual ~TraceNode() {}

protected:
	typedef const char *(TraceNode::*renderer)(struct out_fd* out, RenderingMode mode) const;
};


// A class representing a node whose formatting is uniform throughout
class AtomicValueNode  : public TraceNode {
public:
	const char *outFormattedValue(struct out_fd* out, RenderingMode mode) const;
	const char *outFormattedHexValue(struct out_fd* out, RenderingMode mode) const;
	const char *outFormattedDescription(struct out_fd* out, RenderingMode mode) const;
	const char *outFormattingSuffix(struct out_fd* out, RenderingMode mode) const;

	// Special formatting for invalid values.
	const char *outFormattingInvalidPrefix(struct out_fd* out, RenderingMode mode) const;
	const char *outFormattingInvalidSuffix(struct out_fd* out, RenderingMode mode) const;
};

// A class representing a simple scalar value node
class SimpleValueNode : public AtomicValueNode {
public:
	VisualElementType getElementType() const { return VISUAL_SIMPLE_VALUE; }
	const char *outFormattingPrefix(struct out_fd* out, RenderingMode mode) const;
};

class TraceIntegerValueNode : public SimpleValueNode {
	unsigned short m_size;
	bool  m_is_unsigned;
	bool  m_is_hex;
	const char *m_c_signed_type;
	unsigned long long m_value;

public:
	TraceIntegerValueNode(const struct trace_param_descriptor *param, const void *&data);
	const char *outValue(struct out_fd* out) const;
	const char *outHexValue(struct out_fd* out) const;
	const char *outDescription(struct out_fd* out) const;

	static const unsigned ALL_INT_FLAGS = TRACE_PARAM_FLAG_NUM_8 | TRACE_PARAM_FLAG_NUM_16 | TRACE_PARAM_FLAG_NUM_32 | TRACE_PARAM_FLAG_NUM_64;
};

// TODO: Add support for floating-point values as well

// A base class for various kinds of nodes representing individual strings.
class TraceParamGenericStrNode : public AtomicValueNode {
	mutable const char *m_p_last_char;

protected:
	const char *m_str;
	TraceParamGenericStrNode(const char *s);
	const char *getLastChar() const;

public:
	const char *outValue(struct out_fd* out) const;
	bool isEmpty() const { return m_str && ('\0' == *m_str); }
};

class TraceParamCStrNode : public TraceParamGenericStrNode {
public:
	TraceParamCStrNode(const struct trace_param_descriptor *param);
	bool subsequentSeparator() const { return isEmpty() || ('=' != *getLastChar());  }
	VisualElementType getElementType() const { return VISUAL_CSTR; }
	const char *outFormattingPrefix(struct out_fd* out, RenderingMode mode) const;
};

class TraceParamEnumNode : public TraceParamGenericStrNode {
	uint32_t m_num_value;
	bool	 m_value_known; 	// Data for determining the value was supplied.
	trace_type_definition_mapped* m_type;
	const char* getCorrespondingName(const struct trace_parser_buffer_context *context, const char *type_name, unsigned int value);
public:
	TraceParamEnumNode(const trace_parser_buffer_context *context, const struct trace_param_descriptor *param, const void *&data);
	VisualElementType getElementType() const { return VISUAL_ENUM; }
	const char *outValue(struct out_fd* out) const;
	const char *outDescription(struct out_fd* out) const;
	const char *outFormattingPrefix(struct out_fd* out, RenderingMode mode) const;
	bool isKnownType() const			{ return m_type != NULL; }
	const char *getEnumName() const 	{ return m_value_known ? ( isKnownType() ? m_type->def->type_name : "?") : m_str; }
};

class TraceParamNameNode : public TraceParamGenericStrNode {
public:
	TraceParamNameNode(const struct trace_param_descriptor *param);
	const char *outValue(struct out_fd* out) const;
	const char *outFormattingPrefix(struct out_fd* out, RenderingMode mode) const;
	bool subsequentSeparator() const { return false; }
	VisualElementType getElementType() const { return VISUAL_PARAM_NAME; }
};

class TraceParamVStrNode : public AtomicValueNode {
	struct str_fragment {
		unsigned start_offset;
		unsigned length;
	};

	const char *m_base;
	std::vector<str_fragment> m_fragments;

public:
	TraceParamVStrNode(const struct trace_param_descriptor *param, const void *&data);
	const char *outValue(struct out_fd* out) const;
	const char *outFormattingPrefix(struct out_fd* out, RenderingMode mode) const;
	VisualElementType getElementType() const { return VISUAL_VSTR; }
};

// A class representing a node that contains several components, which may be rendered with different formatting
class TraceChainNode : public TraceNode {
protected:
	std::vector<TraceNode *> m_nodes;
	virtual const char *renderNodes(renderer renderer, struct out_fd* out, RenderingMode mode) const;

public:
	TraceChainNode(unsigned n_nodes) : m_nodes(n_nodes, NULL) {}
	~TraceChainNode();

	const char *outFormattedValue(struct out_fd* out, RenderingMode mode) const;
	const char *outFormattedHexValue(struct out_fd* out, RenderingMode mode) const;
	const char *outFormattedDescription(struct out_fd* out, RenderingMode mode) const;

	const char *outValue(struct out_fd* out) const			{ return outFormattedValue( out, RENDER_MODE_PLAIN); }
	const char *outHexValue(struct out_fd* out) const 		{ return outFormattedHexValue( out, RENDER_MODE_PLAIN); }
	const char *outDescription(struct out_fd* out) const	{ return outFormattedDescription( out, RENDER_MODE_PLAIN); }

	const char *outFormattingPrefix(struct out_fd* out, RenderingMode mode __attribute__((unused))) const
		{ return out->buf + out->i; }
	const char *outFormattingSuffix(struct out_fd* out, RenderingMode mode __attribute__((unused))) const
		{ return out->buf + out->i; }

	VisualElementType getElementType() const { return VISUAL_NAMED_VALUE; }
};

class TraceNameValueNode : public TraceChainNode {
public:
	TraceNameValueNode(const struct trace_param_descriptor *param, TraceNode *ValueNode);
};

// A generic base-class that represents a sequence of trace parameters generated from a given format
class TraceParamsByFormatNode : public TraceChainNode {
	unsigned m_bytes_processed;
	void parseParams(const void *&data);

protected:
	unsigned initDescriptor(const trace_parser_buffer_context *context, trace_log_id_t log_id);
	const trace_parser_buffer_context *const m_context;
	const trace_log_descriptor *m_desc;

public:
	TraceParamsByFormatNode(const trace_parser_buffer_context *context, const struct trace_record_typed *rec);
	TraceParamsByFormatNode(const trace_parser_buffer_context *context, const void *&data);
	TraceParamsByFormatNode(const trace_parser_buffer_context *context, trace_log_id_t log_id);
	~TraceParamsByFormatNode();
    unsigned getNumDataBytesProcessed(bool including_log_id = true) const;
};

// A class representing an embedded format that is the result of a class representation inside a trace.
class TraceEmbeddedFormatNode : public TraceParamsByFormatNode {
protected:
	const char *renderNodes(renderer renderer, struct out_fd* out, RenderingMode mode) const;

public:
	TraceEmbeddedFormatNode(const trace_parser_buffer_context *context, const void *&data);
	VisualElementType getElementType() const { return VISUAL_OBJECT; }
};

// A class which holds only the object description for an embedded node.
// Its construction is simpler as it doesn't need to construct an actual format.
class TraceEmbeddedObjectDescription : public TraceChainNode {
protected:
	const char *renderNodes(renderer renderer, struct out_fd* out, RenderingMode mode) const;

public:
	TraceEmbeddedObjectDescription(const char *obj_name);  // Note: obj_name should persist for the lifetime of the TraceEmbeddedObjectDescription
	VisualElementType getElementType() const { return VISUAL_OBJECT; }
};

#endif /* TRACE_NODE_H_ */
