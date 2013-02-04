/*
 * util.h: Various stand-alone functions for getting  and manipulating string representations.
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

#ifndef __UTIL_H__
#define __UTIL_H__

#include <string>

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

std::string& replaceAll(
     std::string &result,
     const std::string& replaceWhat,
     const std::string& replaceWithWhat);

std::string normalizeTypeName(std::string type_str);

std::string getCallExprFunctionName(const clang::CallExpr *CE);

std::string getLiteralExpr(clang::ASTContext &ast, clang::Rewriter *Rewrite, const clang::Stmt *S);


#endif /* __UTIL_H__ */
