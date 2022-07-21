#include <c-utils/vec.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/mman.h>
#include <sys/types.h>

#define PAGE_SIZE 4096

typedef struct Node
{
	char op;

	union
	{
		int const_index;
		struct
		{
			short a;
			short b;
		} children;
	};
} Node;

typedef struct Instruction
{
	short a;
	short b;
	char op;
} Instruction;

int parse_atom(CU_vec(Node) * nodes, CU_vec(double) * constants, char* expr,
	int expr_len)
{
	char buffer[expr_len + 1];
	memcpy(buffer, expr, expr_len);
	buffer[expr_len] = '\0';

	double val = atof(buffer);

	Node node = {
		.op = '=',
		.const_index = CU_vec_push(constants, val),
	};

	return CU_vec_push(nodes, node);
}

int parse_mul(CU_vec(Node) * nodes, CU_vec(double) * constants, char* expr,
	int expr_len)
{
	for (int i = 0; i < expr_len; i++)
	{
		if (expr[i] == '*')
		{
			Node node = {
				.op = '*',
				.children =
					{
						.a = parse_atom(nodes,
							constants, expr, i),
						.b = parse_mul(nodes, constants,
							expr + i + 1,
							expr_len - i - 1),
					},
			};

			return CU_vec_push(nodes, node);
		}
		if (expr[i] == '/')
		{
			Node node = {
				.op = '/',
				.children =
					{
						.a = parse_atom(nodes,
							constants, expr, i),
						.b = parse_mul(nodes, constants,
							expr + i + 1,
							expr_len - i - 1),
					},
			};

			return CU_vec_push(nodes, node);
		}
	}

	return parse_atom(nodes, constants, expr, expr_len);
}

int parse_add(CU_vec(Node) * nodes, CU_vec(double) * constants, char* expr,
	int expr_len)
{
	for (int i = 0; i < expr_len; i++)
	{
		if (expr[i] == '+')
		{
			Node node = {
				.op = '+',
				.children =
					{
						.a = parse_mul(nodes, constants,
							expr, i),
						.b = parse_add(nodes, constants,
							expr + i + 1,
							expr_len - i - 1),
					},
			};

			return CU_vec_push(nodes, node);
		}
		if (expr[i] == '-')
		{
			Node node = {
				.op = '-',
				.children =
					{
						.a = parse_mul(nodes, constants,
							expr, i),
						.b = parse_add(nodes, constants,
							expr + i + 1,
							expr_len - i - 1),
					},
			};

			return CU_vec_push(nodes, node);
		}
	}

	return parse_mul(nodes, constants, expr, expr_len);
}

char* strip_whitespace(char* in)
{
	int buffer_len = 0;
	for (int i = 0; i < strlen(in); i++)
	{
		if (i != ' ' && i != '\n')
			buffer_len += 1;
	}

	char* ret = malloc(sizeof(char) * (buffer_len + 1));

	int j = 0;
	for (int i = 0; i < strlen(in); i++)
		if (in[i] != ' ' && in[i] != '\n')
			ret[j++] = in[i];

	ret[buffer_len] = '\0';
	return ret;
}

int tree_to_instructions(
	CU_vec(Instruction) * instructions, CU_vec(Node) * nodes, int root)
{
	if ((*nodes)[root].op == '=')
	{
		return (*nodes)[root].const_index;
	}
	else
	{
		Instruction inst = {
			.a = tree_to_instructions(
				instructions, nodes, (*nodes)[root].children.a),
			.b = tree_to_instructions(
				instructions, nodes, (*nodes)[root].children.b),
			.op = (*nodes)[root].op,
		};

		CU_vec_push(instructions, inst);
		return inst.a;
	}
}

void encode_rdi_index(CU_vec(unsigned char) * code_buf, int index)
{
	if (index == 0)
	{
		CU_vec_push(code_buf, 0x07);
	}
	else if (index < 128)
	{
		CU_vec_push(code_buf, 0x47);
		CU_vec_push(code_buf, index);
	}
	else
	{
		CU_vec_push(code_buf, 0x87);

		int buf = index;
		for (int i = 0; i < 4; i++)
		{
			unsigned char curr_byte = ((char*) &buf)[i];
			CU_vec_push(code_buf, curr_byte);
		}
	}
}

CU_vec(unsigned char) instructions_to_bytecode(CU_vec(Instruction) instructions)
{
	CU_vec(unsigned char) ret = CU_vec_init(unsigned char, 0);

	for (int i = 0; i < CU_vec_len(instructions); i++)
	{
		CU_vec_push(&ret, 0xf2);
		CU_vec_push(&ret, 0x0f);
		CU_vec_push(&ret, 0x10);
		encode_rdi_index(&ret, instructions[i].a * 8);

		CU_vec_push(&ret, 0xf2);
		CU_vec_push(&ret, 0x0f);

		if (instructions[i].op == '+')
			CU_vec_push(&ret, 0x58);
		else if (instructions[i].op == '-')
			CU_vec_push(&ret, 0x5c);
		else if (instructions[i].op == '*')
			CU_vec_push(&ret, 0x59);
		else if (instructions[i].op == '/')
			CU_vec_push(&ret, 0x5e);

		encode_rdi_index(&ret, instructions[i].b * 8);

		CU_vec_push(&ret, 0xf2);
		CU_vec_push(&ret, 0x0f);
		CU_vec_push(&ret, 0x11);
		encode_rdi_index(&ret, instructions[i].a * 8);
	}

	CU_vec_push(&ret, 0xc3);

	return ret;
}

int main()
{
	CU_vec(Node) nodes = CU_vec_init(Node, 0);
	CU_vec(double) constants = CU_vec_init(double, 0);
	CU_vec(Instruction) instructions = CU_vec_init(Instruction, 0);

	char* expr = strip_whitespace("2 - 3 * 4");
	int root = parse_add(&nodes, &constants, expr, strlen(expr));
	int result_loc = tree_to_instructions(&instructions, &nodes, root);

	CU_vec(unsigned char) bytecode = instructions_to_bytecode(instructions);
	int numPages = (CU_vec_len(bytecode) / PAGE_SIZE) + 1;

	void (*func)(double* constants) =
		aligned_alloc(PAGE_SIZE, PAGE_SIZE * numPages);
	mprotect(
		func, numPages * PAGE_SIZE, PROT_EXEC | PROT_READ | PROT_WRITE);
	memcpy(func, bytecode, CU_vec_len(bytecode));

	func(constants);
	float ret = constants[result_loc];
	printf("%f\n", ret);

	CU_vec_free(nodes);
	CU_vec_free(constants);
	CU_vec_free(instructions);
	CU_vec_free(bytecode);
	free(expr);
	free(func);
}
