// Copyright 2015, 2016 Ethcore (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.
use aster;

use syntax::ast::{
	MetaItem,
	Item,
	Ident,
};

use syntax::ast;
use syntax::codemap::Span;
use syntax::ext::base::{Annotatable, ExtCtxt};
use syntax::ptr::P;

pub struct Error;

use super::codegen;

pub fn expand_serialization_implementation(
	cx: &mut ExtCtxt,
	span: Span,
	meta_item: &MetaItem,
	annotatable: &Annotatable,
	push: &mut FnMut(Annotatable)
) {
	let item = match *annotatable {
		Annotatable::Item(ref item) => item,
		_ => {
			cx.span_err(meta_item.span, "`#[derive(Binary)]` may only be applied to structs and enums");
			return;
		},
	};

	let builder = aster::AstBuilder::new().span(span);

	let impl_item = match serialize_item(cx, &builder, &item) {
		Ok(item) => item,
		Err(Error) => {
			// An error occured, but it should have been reported already.
			return;
		},
	};

	push(Annotatable::Item(impl_item))
}

fn serialize_item(
	cx: &ExtCtxt,
	builder: &aster::AstBuilder,
	item: &Item,
) -> Result<P<ast::Item>, Error> {
	let generics = match item.node {
		ast::ItemKind::Struct(_, ref generics) => generics,
		ast::ItemKind::Enum(_, ref generics) => generics,
		_ => {
			cx.span_err(
				item.span,
				"`#[derive(Binary)]` may only be applied to structs and enums");
			return Err(Error);
		},
	};

	let ty = builder.ty().path()
		.segment(item.ident).with_generics(generics.clone()).build()
		.build();

	let where_clause = &generics.where_clause;

	let binary_expressions = try!(binary_expr(cx,
		&builder,
		&item,
		&generics,
		ty.clone()));

	let (size_expr, read_expr, write_expr) =
		(binary_expressions.size, binary_expressions.read, binary_expressions.write);

	Ok(quote_item!(cx,
		impl $generics ::ipc::BinaryConvertable for $ty $where_clause {
			fn size(&self) -> usize {
				$size_expr
			}

			fn to_bytes(&self, buffer: &mut [u8], length_stack: &mut VecDeque<usize>) -> Result<(), BinaryConvertError> {
				$write_expr
			}

			fn from_bytes(buffer: &[u8], length_stack: &mut VecDeque<usize>) -> Result<Self, BinaryConvertError> {
				$read_expr
			}

			fn len_params() -> usize {
				1
			}
        }
    ).unwrap())
}

#[allow(unreachable_code)]
fn binary_expr(
	cx: &ExtCtxt,
	builder: &aster::AstBuilder,
	item: &Item,
	impl_generics: &ast::Generics,
	ty: P<ast::Ty>,
) -> Result<BinaryExpressions, Error> {
	match item.node {
		ast::ItemKind::Struct(ref variant_data, _) => {
			binary_expr_item_struct(
				cx,
				builder,
				impl_generics,
				ty,
				item.span,
				variant_data,
			)
		},
		ast::ItemKind::Enum(ref enum_def, _) => {
			binary_expr_enum(
				cx,
				builder,
				item.ident,
				impl_generics,
				ty,
				item.span,
				enum_def,
			)
		},
		_ => {
			cx.span_bug(item.span,
						"expected ItemStruct or ItemEnum in #[derive(Binary)]");
			Err(Error)
		},
	}
}

struct BinaryExpressions {
	pub size: P<ast::Expr>,
	pub write: P<ast::Expr>,
	pub read: P<ast::Expr>,
}

fn replace_qualified(s: &str) -> String {
	if let Some(pos) = s.find("<") {
		let mut source = s.to_owned();
		source.insert(pos, ':');
		source.insert(pos, ':');
		source
	}
	else { s.to_owned() }
}

fn binary_expr_struct(
	cx: &ExtCtxt,
	builder: &aster::AstBuilder,
	ty: P<ast::Ty>,
	fields: &[ast::StructField],
	value_ident: Option<ast::Ident>,
	instance_ident: Option<ast::Ident>,
) -> Result<BinaryExpressions, Error> {

	let size_exprs: Vec<P<ast::Expr>> = fields.iter().enumerate().map(|(index, field)| {
		let raw_ident = ::syntax::print::pprust::ty_to_string(&codegen::strip_ptr(&field.ty));
		let index_ident = builder.id(format!("__field{}", index));
		match raw_ident.as_ref() {
			"u8" => {
				quote_expr!(cx, 1)
			},
			"[u8]" => {
				value_ident.and_then(|x| {
						let field_id = builder.id(field.ident.unwrap());
						Some(quote_expr!(cx, $x. $field_id .len()))
					})
					.unwrap_or_else(|| {
						quote_expr!(cx, $index_ident .len())
					}
				)
			}
			_ => {
				let field_type_ident = builder.id(
					&::syntax::print::pprust::ty_to_string(&codegen::strip_ptr(&field.ty)));

				let field_type_ident_qualified = builder.id(
					replace_qualified(&::syntax::print::pprust::ty_to_string(&codegen::strip_ptr(&field.ty))));

				value_ident.and_then(|x|
					{
						let field_id = builder.id(field.ident.unwrap());
						Some(quote_expr!(cx,
							match $field_type_ident_qualified::len_params() {
								0 => mem::size_of::<$field_type_ident>(),
								_ => $x. $field_id .size(),
							}))
					})
					.unwrap_or_else(|| {
						quote_expr!(cx, match $field_type_ident_qualified::len_params() {
							0 => mem::size_of::<$field_type_ident>(),
							_ => $index_ident .size(),
						})
					})
			}
		}
	}).collect();

	let first_size_expr = size_exprs[0].clone();
	let mut total_size_expr = quote_expr!(cx, 0usize + $first_size_expr);
	for index in 1..size_exprs.len() {
		let next_expr = size_exprs[index].clone();
		total_size_expr = quote_expr!(cx, $total_size_expr + $next_expr);
	}

	let mut write_stmts = Vec::<ast::Stmt>::new();
	write_stmts.push(quote_stmt!(cx, let mut offset = 0usize;).unwrap());

	let mut map_stmts = Vec::<ast::Stmt>::new();
	let field_amount = builder.id(&format!("{}",fields.len()));
	map_stmts.push(quote_stmt!(cx, let mut map = vec![0usize; $field_amount];).unwrap());
	map_stmts.push(quote_stmt!(cx, let mut total = 0usize;).unwrap());
	for (index, field) in fields.iter().enumerate() {
		let field_type_ident = builder.id(
			&::syntax::print::pprust::ty_to_string(&codegen::strip_ptr(&field.ty)));

		let field_type_ident_qualified = builder.id(
			replace_qualified(&::syntax::print::pprust::ty_to_string(&codegen::strip_ptr(&field.ty))));

		let member_expr = match value_ident {
			Some(x) => {
				let field_id = builder.id(field.ident.unwrap());
				quote_expr!(cx, $x . $field_id)
			},
			None => {
				let index_ident = builder.id(format!("__field{}", index));
				quote_expr!(cx, $index_ident)
			},
		};

		let raw_ident = ::syntax::print::pprust::ty_to_string(&codegen::strip_ptr(&field.ty));
		match raw_ident.as_ref() {
			"u8" => {
				write_stmts.push(quote_stmt!(cx, let next_line = offset + 1;).unwrap());
				write_stmts.push(quote_stmt!(cx, buffer[offset] = $member_expr; ).unwrap());
			},
			"[u8]" => {
				write_stmts.push(quote_stmt!(cx, let size = $member_expr .len();).unwrap());
				write_stmts.push(quote_stmt!(cx, let next_line = offset + size;).unwrap());
				write_stmts.push(quote_stmt!(cx, length_stack.push_back(size);).unwrap());
				write_stmts.push(quote_stmt!(cx, buffer[offset..next_line].clone_from_slice($member_expr); ).unwrap());
			}
			_ => {
				write_stmts.push(quote_stmt!(cx, let next_line = offset + match $field_type_ident_qualified::len_params() {
						0 => mem::size_of::<$field_type_ident>(),
						_ => { let size = $member_expr .size(); length_stack.push_back(size); size },
					}).unwrap());
				write_stmts.push(quote_stmt!(cx,
					if let Err(e) = $member_expr .to_bytes(&mut buffer[offset..next_line], length_stack) { return Err(e) };).unwrap());
			}
		}

		write_stmts.push(quote_stmt!(cx, offset = next_line; ).unwrap());

		let field_index = builder.id(&format!("{}", index));
		map_stmts.push(quote_stmt!(cx, map[$field_index] = total;).unwrap());

		match raw_ident.as_ref() {
			"u8" => {
				map_stmts.push(quote_stmt!(cx, total += 1;).unwrap());
			},
			"[u8]" => {
				map_stmts.push(quote_stmt!(cx, let size = length_stack.pop_front().unwrap();).unwrap());
				map_stmts.push(quote_stmt!(cx, total += size;).unwrap());
			},
			_ => {
				map_stmts.push(quote_stmt!(cx, let size = match $field_type_ident_qualified::len_params() {
						0 => mem::size_of::<$field_type_ident>(),
						_ => length_stack.pop_front().unwrap(),
					}).unwrap());
				map_stmts.push(quote_stmt!(cx, total += size;).unwrap());
			}
		}
	};

	let read_expr = match fields.iter().any(|f| codegen::has_ptr(&f.ty)) {
		true => {
			// cannot create structs with pointers
			quote_expr!(cx, Err(::ipc::binary::BinaryConvertError))
		},
		false => {
			if value_ident.is_some() {
				let instance_create = named_fields_sequence(cx, &ty, fields);
				quote_expr!(cx, { $map_stmts; $instance_create; Ok(result) })
			}
			else {
				let map_variant = P(fields_sequence(cx, &ty, fields, &instance_ident.unwrap_or(builder.id("Self"))));
				quote_expr!(cx, { $map_stmts; Ok($map_variant) })
			}
		},
	};

    Ok(BinaryExpressions {
		size: total_size_expr,
		write: quote_expr!(cx, { $write_stmts; Ok(()) } ),
		read: read_expr,
	})
}

#[allow(unreachable_code)]
fn binary_expr_item_struct(
	cx: &ExtCtxt,
	builder: &aster::AstBuilder,
	_impl_generics: &ast::Generics,
	ty: P<ast::Ty>,
	span: Span,
	variant_data: &ast::VariantData,
) -> Result<BinaryExpressions, Error> {
	match *variant_data {
		ast::VariantData::Tuple(ref fields, _) => {
			binary_expr_struct(
				cx,
				&builder,
				ty,
				fields,
				Some(builder.id("self")),
				None,
			)
		},
		ast::VariantData::Struct(ref fields, _) => {
			binary_expr_struct(
				cx,
				&builder,
				ty,
				fields,
				Some(builder.id("self")),
				None,
			)
		},
		_ => {
			cx.span_bug(span,
				&format!("#[derive(Binary)] Unsupported struct content, expected tuple/struct, found: {:?}",
					variant_data));
			Err(Error)
		},
	}
}

fn binary_expr_enum(
	cx: &ExtCtxt,
	builder: &aster::AstBuilder,
	type_ident: Ident,
	impl_generics: &ast::Generics,
	ty: P<ast::Ty>,
	span: Span,
	enum_def: &ast::EnumDef,
) -> Result<BinaryExpressions, Error> {
	let arms: Vec<_> = try!(
		enum_def.variants.iter()
			.enumerate()
			.map(|(variant_index, variant)| {
				binary_expr_variant(
					cx,
					builder,
					type_ident,
					impl_generics,
					ty.clone(),
					span,
					variant,
					variant_index,
				)
			})
			.collect()
	);

	let (size_arms, write_arms, mut read_arms) = (
		arms.iter().map(|x| x.size.clone()).collect::<Vec<ast::Arm>>(),
		arms.iter().map(|x| x.write.clone()).collect::<Vec<ast::Arm>>(),
		arms.iter().map(|x| x.read.clone()).collect::<Vec<ast::Arm>>());

	read_arms.push(quote_arm!(cx, _ => { Err(BinaryConvertError) } ));

	Ok(BinaryExpressions {
		size: quote_expr!(cx, 1usize + match *self { $size_arms }),
		write: quote_expr!(cx, match *self { $write_arms }; ),
		read: quote_expr!(cx, match buffer[0] { $read_arms }),
	})
}

struct BinaryArm {
	size: ast::Arm,
	write: ast::Arm,
	read: ast::Arm,
}

fn fields_sequence(
	ext_cx: &ExtCtxt,
	_ty: &P<ast::Ty>,
	fields: &[ast::StructField],
	variant_ident: &ast::Ident,
) -> ast::Expr {
	use syntax::parse::token;
	use syntax::ast::TokenTree::Token;

	let named_members = fields.iter().any(|f| f.ident.is_some());

	::quasi::parse_expr_panic(&mut ::syntax::parse::new_parser_from_tts(
		ext_cx.parse_sess(),
		ext_cx.cfg(),
		{
			let _sp = ext_cx.call_site();
			let mut tt = ::std::vec::Vec::new();
			tt.push(Token(_sp, token::Ident(variant_ident.clone())));
			if named_members {
				tt.push(Token(_sp, token::OpenDelim(token::Brace)));
			}
			else {
				tt.push(Token(_sp, token::OpenDelim(token::Paren)));
			}

			for (idx, field) in fields.iter().enumerate() {
				if field.ident.is_some() {
					tt.push(Token(_sp, token::Ident(field.ident.clone().unwrap())));
					tt.push(Token(_sp, token::Colon));
				}

				// special case for u8, it just takes byte form sequence
				if ::syntax::print::pprust::ty_to_string(&field.ty) == "u8" {
					tt.push(Token(_sp, token::Ident(ext_cx.ident_of("buffer"))));

					tt.push(Token(_sp, token::OpenDelim(token::Bracket)));
					tt.push(Token(_sp, token::Ident(ext_cx.ident_of("map"))));
					tt.push(Token(_sp, token::OpenDelim(token::Bracket)));
					tt.push(Token(_sp, token::Ident(ext_cx.ident_of(&format!("{}", idx)))));
					tt.push(Token(_sp, token::CloseDelim(token::Bracket)));
					tt.push(Token(_sp, token::CloseDelim(token::Bracket)));

					tt.push(Token(_sp, token::Comma));
					continue;
				}

				// special case for [u8], it just takes a byte sequence
				if ::syntax::print::pprust::ty_to_string(&field.ty) == "[u8]" {
					tt.push(Token(_sp, token::Ident(ext_cx.ident_of("buffer"))));

					tt.push(Token(_sp, token::OpenDelim(token::Bracket)));
					tt.push(Token(_sp, token::Ident(ext_cx.ident_of("map"))));
					tt.push(Token(_sp, token::OpenDelim(token::Bracket)));
					tt.push(Token(_sp, token::Ident(ext_cx.ident_of(&format!("{}", idx)))));
					tt.push(Token(_sp, token::CloseDelim(token::Bracket)));
					tt.push(Token(_sp, token::DotDot));

					if idx+1 != fields.len() {
						tt.push(Token(_sp, token::Ident(ext_cx.ident_of("map"))));
						tt.push(Token(_sp, token::OpenDelim(token::Bracket)));
						tt.push(Token(_sp, token::Ident(ext_cx.ident_of(&format!("{}", idx+1)))));
						tt.push(Token(_sp, token::CloseDelim(token::Bracket)));
					}

					tt.push(Token(_sp, token::CloseDelim(token::Bracket)));

					tt.push(Token(_sp, token::Comma));
					continue;
				}

				tt.push(Token(_sp, token::Ident(ext_cx.ident_of("try!"))));
				tt.push(Token(_sp, token::OpenDelim(token::Paren)));
				tt.push(
					Token(
						_sp,
						token::Ident(ext_cx.ident_of(&replace_qualified(&::syntax::print::pprust::ty_to_string(&field.ty))))
					));
				tt.push(Token(_sp, token::ModSep));
				tt.push(Token(_sp, token::Ident(ext_cx.ident_of("from_bytes"))));
				tt.push(Token(_sp, token::OpenDelim(token::Paren)));

				tt.push(Token(_sp, token::BinOp(token::And)));

				tt.push(Token(_sp, token::Ident(ext_cx.ident_of("buffer"))));

				tt.push(Token(_sp, token::OpenDelim(token::Bracket)));
				tt.push(Token(_sp, token::Ident(ext_cx.ident_of("map"))));
				tt.push(Token(_sp, token::OpenDelim(token::Bracket)));
				tt.push(Token(_sp, token::Ident(ext_cx.ident_of(&format!("{}", idx)))));
				tt.push(Token(_sp, token::CloseDelim(token::Bracket)));
				tt.push(Token(_sp, token::DotDot));

				if idx+1 != fields.len() {
					tt.push(Token(_sp, token::Ident(ext_cx.ident_of("map"))));
					tt.push(Token(_sp, token::OpenDelim(token::Bracket)));
					tt.push(Token(_sp, token::Ident(ext_cx.ident_of(&format!("{}", idx+1)))));
					tt.push(Token(_sp, token::CloseDelim(token::Bracket)));
				}

				tt.push(Token(_sp, token::CloseDelim(token::Bracket)));

				tt.push(Token(_sp, token::Comma));
				tt.push(Token(_sp, token::Ident(ext_cx.ident_of("length_stack"))));

				tt.push(Token(_sp, token::CloseDelim(token::Paren)));
				tt.push(Token(_sp, token::CloseDelim(token::Paren)));
				tt.push(Token(_sp, token::Comma));
			}
			if named_members {
				tt.push(Token(_sp, token::CloseDelim(token::Brace)));
			}
			else {
				tt.push(Token(_sp, token::CloseDelim(token::Paren)));
			}
			tt
		})
	).unwrap()
}

fn named_fields_sequence(
	ext_cx: &ExtCtxt,
	ty: &P<ast::Ty>,
	fields: &[ast::StructField],
) -> ast::Stmt {
	use syntax::parse::token;
	use syntax::ast::TokenTree::Token;

	::quasi::parse_stmt_panic(&mut ::syntax::parse::new_parser_from_tts(
		ext_cx.parse_sess(),
		ext_cx.cfg(),
		{
			let _sp = ext_cx.call_site();
			let mut tt = ::std::vec::Vec::new();
			tt.push(Token(_sp, token::Ident(ext_cx.ident_of("let"))));
			tt.push(Token(_sp, token::Ident(ext_cx.ident_of("result"))));
			tt.push(Token(_sp, token::Eq));

			tt.push(Token(
				_sp,
			  	token::Ident(
					ext_cx.ident_of(&::syntax::print::pprust::ty_to_string(ty))
			 		)));

			tt.push(Token(_sp, token::OpenDelim(token::Brace)));

			for (idx, field) in fields.iter().enumerate() {
				tt.push(Token(_sp, token::Ident(field.ident.clone().unwrap())));
				tt.push(Token(_sp, token::Colon));

				// special case for u8, it just takes byte form sequence
				if ::syntax::print::pprust::ty_to_string(&field.ty) == "u8" {
					tt.push(Token(_sp, token::Ident(ext_cx.ident_of("buffer"))));

					tt.push(Token(_sp, token::OpenDelim(token::Bracket)));
					tt.push(Token(_sp, token::Ident(ext_cx.ident_of("map"))));
					tt.push(Token(_sp, token::OpenDelim(token::Bracket)));
					tt.push(Token(_sp, token::Ident(ext_cx.ident_of(&format!("{}", idx)))));
					tt.push(Token(_sp, token::CloseDelim(token::Bracket)));
					tt.push(Token(_sp, token::CloseDelim(token::Bracket)));

					tt.push(Token(_sp, token::Comma));
					continue;
				}

				// special case for [u8], it just takes a byte sequence
				if ::syntax::print::pprust::ty_to_string(&field.ty) == "[u8]" {
					tt.push(Token(_sp, token::Ident(ext_cx.ident_of("buffer"))));

					tt.push(Token(_sp, token::OpenDelim(token::Bracket)));
					tt.push(Token(_sp, token::Ident(ext_cx.ident_of("map"))));
					tt.push(Token(_sp, token::OpenDelim(token::Bracket)));
					tt.push(Token(_sp, token::Ident(ext_cx.ident_of(&format!("{}", idx)))));
					tt.push(Token(_sp, token::CloseDelim(token::Bracket)));
					tt.push(Token(_sp, token::DotDot));

					if idx+1 != fields.len() {
						tt.push(Token(_sp, token::Ident(ext_cx.ident_of("map"))));
						tt.push(Token(_sp, token::OpenDelim(token::Bracket)));
						tt.push(Token(_sp, token::Ident(ext_cx.ident_of(&format!("{}", idx+1)))));
						tt.push(Token(_sp, token::CloseDelim(token::Bracket)));
					}

					tt.push(Token(_sp, token::CloseDelim(token::Bracket)));

					tt.push(Token(_sp, token::Comma));
					continue;
				}

				tt.push(Token(_sp, token::Ident(ext_cx.ident_of("try!"))));
				tt.push(Token(_sp, token::OpenDelim(token::Paren)));
				tt.push(Token(
					_sp,
					token::Ident(
						ext_cx.ident_of(&replace_qualified(&::syntax::print::pprust::ty_to_string(&field.ty)))
						)));
				tt.push(Token(_sp, token::ModSep));
				tt.push(Token(_sp, token::Ident(ext_cx.ident_of("from_bytes"))));
				tt.push(Token(_sp, token::OpenDelim(token::Paren)));

				tt.push(Token(_sp, token::BinOp(token::And)));
				tt.push(Token(_sp, token::Ident(ext_cx.ident_of("buffer"))));

				tt.push(Token(_sp, token::OpenDelim(token::Bracket)));
				tt.push(Token(_sp, token::Ident(ext_cx.ident_of("map"))));
				tt.push(Token(_sp, token::OpenDelim(token::Bracket)));
				tt.push(Token(_sp, token::Ident(ext_cx.ident_of(&format!("{}", idx)))));
				tt.push(Token(_sp, token::CloseDelim(token::Bracket)));
				tt.push(Token(_sp, token::DotDot));
				if idx + 1 != fields.len() {
					tt.push(Token(_sp, token::Ident(ext_cx.ident_of("map"))));
					tt.push(Token(_sp, token::OpenDelim(token::Bracket)));
					tt.push(Token(_sp, token::Ident(ext_cx.ident_of(&format!("{}", idx+1)))));
					tt.push(Token(_sp, token::CloseDelim(token::Bracket)));
				}

				tt.push(Token(_sp, token::CloseDelim(token::Bracket)));

				tt.push(Token(_sp, token::Comma));
				tt.push(Token(_sp, token::Ident(ext_cx.ident_of("length_stack"))));


				tt.push(Token(_sp, token::CloseDelim(token::Paren)));
				tt.push(Token(_sp, token::CloseDelim(token::Paren)));
				tt.push(Token(_sp, token::Comma));
			}

			tt.push(Token(_sp, token::CloseDelim(token::Brace)));
			tt
		})
	).unwrap()
}

fn binary_expr_variant(
	cx: &ExtCtxt,
	builder: &aster::AstBuilder,
	type_ident: Ident,
	_generics: &ast::Generics,
	ty: P<ast::Ty>,
	_span: Span,
	variant: &ast::Variant,
	variant_index: usize,
) -> Result<BinaryArm, Error> {
	let variant_ident = variant.node.name;
	let variant_index_ident = builder.id(format!("{}", variant_index));

	match variant.node.data {
		ast::VariantData::Unit(_) => {
			let pat = builder.pat().path()
				.id(type_ident).id(variant_ident)
				.build();

			let variant_val = builder.id(format!("{}::{}", type_ident, variant_ident));

			Ok(BinaryArm {
				size: quote_arm!(cx, $pat => { 0usize } ),
				write: quote_arm!(cx, $pat => { buffer[0] = $variant_index_ident; Ok(()) } ),
				read: quote_arm!(cx, $variant_index_ident => { Ok($variant_val) } ),
			})
		},
		ast::VariantData::Tuple(ref fields, _) => {
			let field_names: Vec<ast::Ident> = (0 .. fields.len())
				.map(|i| builder.id(format!("__field{}", i)))
				.collect();

			let pat = builder.pat().enum_()
				.id(type_ident).id(variant_ident).build()
				.with_pats(
					field_names.iter()
						.map(|field| builder.pat().ref_id(field))
				)
				.build();

			let binary_expr = try!(binary_expr_struct(
				cx,
				&builder,
				ty,
				fields,
				None,
				Some(builder.id(format!("{}::{}", type_ident, variant_ident))),
			));

			let (size_expr, write_expr, read_expr) = (binary_expr.size, vec![binary_expr.write], binary_expr.read);
			Ok(BinaryArm {
				size: quote_arm!(cx, $pat => { $size_expr } ),
				write: quote_arm!(cx,
					$pat => {
						buffer[0] = $variant_index_ident;
						let buffer = &mut buffer[1..];
						$write_expr
				}),
				read: quote_arm!(cx, $variant_index_ident => { $read_expr } ),
			})
		},
		ast::VariantData::Struct(ref fields, _) => {
			let field_names: Vec<_> = (0 .. fields.len())
				.map(|i| builder.id(format!("__field{}", i)))
				.collect();

			let pat = builder.pat().struct_()
				.id(type_ident).id(variant_ident).build()
				.with_pats(
					field_names.iter()
						.zip(fields.iter())
						.map(|(id, field)|(field.ident.unwrap(), builder.pat().ref_id(id))))
				.build();

			let binary_expr = try!(binary_expr_struct(
				cx,
				&builder,
				ty,
				fields,
				None,
				Some(builder.id(format!("{}::{}", type_ident, variant_ident))),
			));

			let (size_expr, write_expr, read_expr) = (binary_expr.size, vec![binary_expr.write], binary_expr.read);

			Ok(BinaryArm {
				size: quote_arm!(cx, $pat => { $size_expr } ),
				write: quote_arm!(cx,
					$pat => {
						buffer[0] = $variant_index_ident;
						let buffer = &mut buffer[1..];
						$write_expr
				}),
				read: quote_arm!(cx, $variant_index_ident => { $read_expr } ),
			})
		},
	}
}
