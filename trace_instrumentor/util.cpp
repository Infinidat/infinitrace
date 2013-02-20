/*
 * util.cpp: Various stand-alone functions for getting  and manipulating string representations.
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


#include "util.h"

using namespace clang;

std::string getLiteralExpr(ASTContext &ast, Rewriter *Rewrite, const clang::Stmt *S)
{
    SourceManager *SM = &ast.getSourceManager();
    int Size = Rewrite->getRangeSize(S->getSourceRange());
    if (Size == -1) {
        return std::string("");
    }

    const char *startBuf = SM->getCharacterData(S->getLocStart());
    return std::string(startBuf, Size);
}

std::string normalizeTypeName(std::string type_str) {
    std::string replaced = replaceAll(type_str, " ", "_");
    return replaceAll(replaced, ":", "_");
}

static inline bool isCPlusPlus(LangOptions const& langOpts)
{
    return langOpts.CPlusPlus != 0;
}

std::string castTo(LangOptions const& langOpts, const std::string& orig_expr, const std::string& cast_type)
{
     if (isCPlusPlus(langOpts)) {
         return "reinterpret_cast<" + cast_type + ">(" + orig_expr + ")";
     } else {
         return "(" + cast_type + ") (" + orig_expr + ")";
     }
}

std::string getCallExprFunctionName(const clang::CallExpr *CE)
{
    const FunctionDecl *callee = CE->getDirectCallee();
    if (NULL == callee) {
        return std::string();
    }

    return callee->getQualifiedNameAsString();
}

std::string& replaceAll(
     std::string &result,
     const std::string& replaceWhat,
     const std::string& replaceWithWhat)
 {
     while(1)
     {
         const int pos = result.find(replaceWhat);
         if (pos==-1) break;
         result.replace(pos,replaceWhat.size(),replaceWithWhat);
     }
     return result;
 }
