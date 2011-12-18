/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
      but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "config.h"

#include "kismet_json.h"

void JSON_delete(struct JSON_value *v) {
	for (unsigned int x = 0; x < v->value_array.size(); x++) {
		JSON_delete(v->value_array[x]);
	}

	for (map<string, struct JSON_value *>::iterator x = v->value_map.begin();
		 x != v->value_map.end(); ++x) {
		JSON_delete(x->second);
	}

	delete(v);
}

struct JSON_value *JSON_parse(string in_json, string& error) {
	vector<JSON_token> tok_vec;
	struct JSON_value *ret = NULL;
	JSON_token tk;

	JSON_token_type expected = JSON_unknown;

	int tk_st_escaped = 0;

	// Nested stack of values
	vector<struct JSON_value *> value_stack;
	vector<JSON_token *> symbol_stack;
	// Current block we're adding values to
	struct JSON_value *cur_val = NULL;
	// JSON token we're getting the symbol name from
	JSON_token *sym_tok = NULL;

	tk.tok_type = JSON_unknown;
	tk.tok_str = "";
	tk.tok_position = 0;

	error = "";

	// Step one, tokenize the input
	for (unsigned int x = 0; x < in_json.length(); x++) {
		if (tk_st_escaped > 0)
			tk_st_escaped--;

		if (in_json[x] == '\\' && !tk_st_escaped) {
			tk_st_escaped = 2;
		}

		// If we're in a quoted string, not exiting a quoted string, append
		if (tk.tok_type == JSON_quoted && !tk_st_escaped && in_json[x] != '"') {
			tk.tok_str += in_json[x];
			continue;
		} 

		// If we're in a number, we need to end on any separator; otherwise we'll
		// error later
		if (tk.tok_type == JSON_numeric) {
			switch (in_json[x]) {
				case ',':
				case '}':
				case ']':
				case ' ':
					// printf("DEBUG - end number '%s'\n", tk.tok_str.c_str());
					tok_vec.push_back(tk);
					tk.tok_str = "";
					tk.tok_type = JSON_unknown;
					break;
			}
		}

		if (in_json[x] == '"' && !tk_st_escaped) {
			// If we're unknown, this is a new quoted string
			if (tk.tok_type == JSON_unknown) {
				// printf("DEBUG - New quoted string\n");
				tk.tok_type = JSON_quoted;
				tk.tok_position = x;
				continue;
			}
		
			// If we're known, we're ending this token
			if (tk.tok_type == JSON_quoted) {
				// printf("DEBUG - end quoted string '%s'\n", tk.tok_str.c_str());
				tok_vec.push_back(tk);
				tk.tok_str = "";
				tk.tok_type = JSON_unknown;
				continue;
			}
		}

		if (in_json[x] == '{') {
			if (tk.tok_type == JSON_unknown) {
				// printf("DEBUG - {\n");
				tk.tok_type = JSON_start;
				tk.tok_position = x;
				tok_vec.push_back(tk);
				tk.tok_type = JSON_unknown;
				continue;
			}
		}

		if (in_json[x] == '}') {
			if (tk.tok_type == JSON_unknown) {
				// printf("DEBUG - }\n");
				tk.tok_type = JSON_end;
				tk.tok_position = x;
				tok_vec.push_back(tk);
				tk.tok_type = JSON_unknown;
				continue;
			}
		}

		if (in_json[x] == '[') {
			if (tk.tok_type == JSON_unknown) {
				// printf("DEBUG - [\n");
				tk.tok_type = JSON_arrstart;
				tk.tok_position = x;
				tok_vec.push_back(tk);
				tk.tok_type = JSON_unknown;
				continue;
			}
		}

		if (in_json[x] == ']') {
			if (tk.tok_type == JSON_unknown) {
				// printf("DEBUG - ]\n");
				tk.tok_type = JSON_arrend;
				tk.tok_position = x;
				tok_vec.push_back(tk);
				tk.tok_type = JSON_unknown;
				continue;
			}
		}

		if (in_json[x] == ' ') {
			continue;
		}

		if (in_json[x] == ':') {
			if (tk.tok_type == JSON_unknown) {
				// printf("DEBUG - :\n");
				tk.tok_type = JSON_colon;
				tk.tok_position = x;
				tok_vec.push_back(tk);
				tk.tok_type = JSON_unknown;
				continue;
			}
		}

		if (in_json[x] == ',') {
			if (tk.tok_type == JSON_unknown) {
				// printf("DEBUG - ,\n");
				tk.tok_type = JSON_comma;
				tk.tok_position = x;
				tok_vec.push_back(tk);
				tk.tok_type = JSON_unknown;
				continue;
			}
		}

		if (in_json[x] == '-') {
			if (tk.tok_type == JSON_unknown) {
				tk.tok_type = JSON_numeric;
				tk.tok_position = x;
				tk.tok_str += in_json[x];
				continue;
			}
		}

		if (in_json[x] == '.') {
			if (tk.tok_type == JSON_numeric) {
				tk.tok_str += in_json[x];
				continue;
			}
		}

		if (in_json[x] >= '0' && in_json[x] <= '9') {
			if (tk.tok_type == JSON_unknown || tk.tok_type == JSON_numeric) {
				if (tk.tok_type != JSON_numeric)
					tk.tok_position = x;
				tk.tok_type = JSON_numeric;
				tk.tok_str += in_json[x];
				continue;
			}
		}

		if (in_json[x] == 't') {
			// Start looking for token 'true'
			if (in_json.substr(x, 4) == "true") {
				// printf("DEBUG - boolean TRUE\n");
				tk.tok_type = JSON_boolean;
				tk.tok_position = x;
				tk.tok_str = "true";
				tok_vec.push_back(tk);
				tk.tok_type = JSON_unknown;
				tk.tok_str = "";
				x += 3;
				continue;
			}
		}

		if (in_json[x] == 'f') {
			// Start looking for token 'true'
			if (in_json.substr(x, 5) == "false") {
				// printf("DEBUG - boolean FALSE\n");
				tk.tok_type = JSON_boolean;
				tk.tok_position = x;
				tk.tok_str = "false";
				tok_vec.push_back(tk);
				tk.tok_type = JSON_unknown;
				tk.tok_str = "";
				x += 4;
				continue;
			}
		}

		// printf("DEBUG - Unexpected '%c'\n", in_json[x]);
		error = "Unexpected symbol '" + in_json.substr(x, 1) + "' at position " + 
			IntToString(x);
		return ret;
	}

	// Parse the token stream
	expected = JSON_start;
	for (unsigned int x = 0; x < tok_vec.size(); x++) {
		// Debug - print it
#if 0
		switch (tok_vec[x].tok_type) {
			case JSON_unknown:
				printf("Unknown token\n");
				break;
			case JSON_start:
				printf("START {\n");
				break;
			case JSON_end:
				printf("END }\n");
				break;
			case JSON_arrstart:
				printf("START [\n");
				break;
			case JSON_arrend:
				printf("END ]\n");
				break;
			case JSON_colon:
				printf("COLON :\n");
				break;
			case JSON_comma:
				printf("COMMA ,\n");
				break;
			case JSON_quoted:
				printf("STRING '%s'\n", tok_vec[x].tok_str.c_str());
				break;
			case JSON_numeric:
				printf("NUMBER %s\n", tok_vec[x].tok_str.c_str());
				break;
			case JSON_boolean:
				printf("BOOL %s\n", tok_vec[x].tok_str.c_str());
				break;
			default:
				printf("oops\n");
				break;
		}
#endif

		// If we're in the initial state and we don't have anything...
		if (cur_val == NULL) {
			if (tok_vec[x].tok_type == JSON_start) {
				// printf("DEBUG - started initial dictionary\n");

				ret = new struct JSON_value;
				cur_val = ret;

				// Flag that we're a dictionary
				cur_val->value.tok_type = JSON_start;

				// we expect a symbol
				expected = JSON_sym;

				continue;
			}
		} else if (expected == JSON_sym) {
			if (tok_vec[x].tok_type == JSON_quoted) {
				// printf("DEBUG - Got symbol %s\n", tok_vec[x].tok_str.c_str());
				sym_tok = &(tok_vec[x]);

				// "foo":<value>
				expected = JSON_colon;
				continue;
			}
		} else if (expected == JSON_colon) {
			if (tok_vec[x].tok_type == JSON_colon) {
				expected = JSON_value;
				continue;
			}
		} else if (expected == JSON_value) {
			if (tok_vec[x].tok_type == JSON_quoted ||
				tok_vec[x].tok_type == JSON_numeric ||
				tok_vec[x].tok_type == JSON_boolean) {

				// printf("Debug - Got %s=>%s\n", sym_tok->tok_str.c_str(), tok_vec[x].tok_str.c_str()); 

				// Make a value record for it
				struct JSON_value *v = new struct JSON_value;
				v->value = tok_vec[x];

				// If we're in a dictionary, associate it
				if (cur_val->value.tok_type == JSON_start) {
					// printf("  Adding to dictionary\n");
					cur_val->value_map[sym_tok->tok_str] = v;
				} else {
					// printf("  Adding to array\n");
					cur_val->value_array.push_back(v);
				}

				// Expect some sort of separator, either end or comma
				expected = JSON_sep;
				continue;
			} else if (tok_vec[x].tok_type == JSON_start ||
					   tok_vec[x].tok_type == JSON_arrstart) {
#if 0
				if (tok_vec[x].tok_type == JSON_start) 
					printf("DEBUG - starting new sub-dictionary\n");
				else
					printf("DEBUG - starting new array\n");
#endif

				// Create a new container, of whatever type we're starting
				struct JSON_value *v = new struct JSON_value;
				v->value = tok_vec[x];

				// printf("debug - descending to cur_val %p\n", v);

				// Push the current states onto the stack
				value_stack.push_back(cur_val);
				symbol_stack.push_back(sym_tok);

				// Insert it into a dictionary or append to an array based on our
				// current container type
				if (cur_val->value.tok_type == JSON_start) {
					// printf("  Nested under dictionary %s\n", sym_tok->tok_str.c_str());
					cur_val->value_map[sym_tok->tok_str] = v;
				} else {
					// printf("  Adding to array\n");
					cur_val->value_array.push_back(v);
				}

				// Set the next token
				if (tok_vec[x].tok_type == JSON_start)  {
					// If we started a dictionary we need to wipe out the current
					// symbol, and expect a new one
					sym_tok = NULL;
					expected = JSON_sym;
				} else {
					// An array expects another value, symbol is irrelevant
					expected = JSON_value;
				}

				// Shift to the new container type
				cur_val = v;

				continue;
			} else if (tok_vec[x].tok_type == JSON_arrend ||
					   tok_vec[x].tok_type == JSON_end) {
				// If we're ending an array or dictionary, we pop off the current 
				// value from the stack and reset, unless we're at the end of the
				// stack!

				if (cur_val == ret) {
					// printf("debug - end of starting block\n");

					if (x != (tok_vec.size() - 1)) {
						// printf("debug - end of starting block before end of stream\n");

						error = "JSON parser found end of JSON block before the "
							"end of the token stream at " +
							IntToString(tok_vec[x].tok_position);
					}

					// printf("debug - returning successfully!\n");
					return ret;
				} else {
					// printf("DEBUG - end of array/dictionary, popping back\n");
					// Pop back one in the stack
					cur_val = value_stack[value_stack.size() - 1];
					value_stack.erase(value_stack.begin() + value_stack.size() - 1);
					sym_tok = symbol_stack[symbol_stack.size() - 1];
					symbol_stack.erase(symbol_stack.begin() + symbol_stack.size() - 1);
					// printf("debug - popped bck to cur_val %p\n", cur_val);
				}

				// We retain the expectation of a separator...
				// printf("debug - ended block, expected %d\n", expected);
				expected = JSON_sep;
				continue;
			}
		} else if (expected == JSON_sep) {
			if (tok_vec[x].tok_type == JSON_comma) {
				if (cur_val->value.tok_type == JSON_start) {
					// If we're a dictionary we need a new symbol
					expected = JSON_sym;
					continue;
				} else {
					// We want another value
					expected = JSON_value;
					continue;
				}
			} else if (tok_vec[x].tok_type == JSON_arrend ||
					   tok_vec[x].tok_type == JSON_end) {
				// If we're ending an array or dictionary, we pop off the current 
				// value from the stack and reset, unless we're at the end of the
				// stack!

				if (cur_val == ret) {
					// printf("debug - end of starting block\n");

					if (x != (tok_vec.size() - 1)) {
						// printf("debug - end of starting block before end of stream\n");

						error = "JSON parser found end of JSON block before the "
							"end of the token stream at " +
							IntToString(tok_vec[x].tok_position);
					}

					// printf("debug - returning successfully!\n");
					return ret;
				} else {
					// printf("DEBUG - end of array/dictionary, popping back\n");
					// Pop back one in the stack
					cur_val = value_stack[value_stack.size() - 1];
					value_stack.erase(value_stack.begin() + value_stack.size() - 1);
					sym_tok = symbol_stack[symbol_stack.size() - 1];
					symbol_stack.erase(symbol_stack.begin() + symbol_stack.size() - 1);
					// printf("debug - popped bck to cur_val %p\n", cur_val);
				}

				// We retain the expectation of a separator...
				// printf("debug - ended block, expected %d\n", expected);
				expected = JSON_sep;
				continue;
			}
		}
				
		// printf("debug - end of line, got %d wanted %d\n", tok_vec[x].tok_type, expected);
		error = "JSON parser got unexpected data at " + 
			IntToString(tok_vec[x].tok_position);
		return ret;
	}

	return ret;
}

void JSON_dump(struct JSON_value *jsonv, string key, int depth) {
	string d;

	for (int x = 0; x < depth; x++)
		d += " ";

	// printf("%sValue type: %d\n", d.c_str(), jsonv->value.tok_type);
	if (jsonv->value.tok_type == JSON_start) {
		printf("%sDictionary\n", d.c_str());
		for (map<string, struct JSON_value *>::iterator x = jsonv->value_map.begin();
			 x != jsonv->value_map.end(); ++x) {
			JSON_dump(x->second, x->first + string(" => "), depth + 1);
		}
	} else if (jsonv->value.tok_type == JSON_arrstart) {
		printf("%s%sArray\n", d.c_str(), key.c_str());
		for (unsigned int x = 0; x < jsonv->value_array.size(); x++) {
			JSON_dump(jsonv->value_array[x], "", depth + 1);
		}
	} else if (jsonv->value.tok_type == JSON_quoted) {
		printf("%s%s'%s'\n", d.c_str(), key.c_str(), jsonv->value.tok_str.c_str());
	} else if (jsonv->value.tok_type == JSON_numeric) {
		printf("%s%s%s\n", d.c_str(), key.c_str(), jsonv->value.tok_str.c_str());
	} else if (jsonv->value.tok_type == JSON_boolean) {
		printf("%s%s%s\n", d.c_str(), key.c_str(), jsonv->value.tok_str.c_str());
	}
}

struct JSON_value *JSON_dict_get_value(struct JSON_value *in_parent, string in_key,
									   string& error) {
	map<string, struct JSON_value *>::iterator vitr;

	error = "";

	if (in_parent == NULL) {
		error = "JSON dictionary parent doesn't exist";
		return NULL;
	}

	if (in_parent->value.tok_type != JSON_start) {
		error = "JSON parent at " + IntToString(in_parent->value.tok_position) + 
			" not a dictionary";
		return NULL;
	} 

	if ((vitr = in_parent->value_map.find(in_key)) == in_parent->value_map.end()) {
		error = "JSON no such key '" + in_key + "' in dictionary";
		return NULL;
	}

	return vitr->second;
}

string JSON_dict_get_string(struct JSON_value *in_parent, string in_key,
							string& error) {
	struct JSON_value *v = JSON_dict_get_value(in_parent, in_key, error);
	
	error = "";

	if (error.length() != 0)
		return "";

	if (v == NULL)
		return "";

	return v->value.tok_str;
}

float JSON_dict_get_number(struct JSON_value *in_parent, string in_key,
						   string& error) {
	float f = 0.0f;
	string v = JSON_dict_get_string(in_parent, in_key, error);

	error = "";

	if (error.length() != 0)
		return f;

	if (v == "true") 
		return 1.0f;

	if (v == "false")
		return 0.0f;

	if (sscanf(v.c_str(), "%f", &f) != 1) {
		error = "JSON expected a numerical value but didn't get one";
		return 0.0f;
	}

	return f;
}

