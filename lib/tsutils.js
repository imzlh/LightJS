var ContextualKeyword;
(function (ContextualKeyword) {
    ContextualKeyword[ContextualKeyword["NONE"] = 0] = "NONE";
    ContextualKeyword[ContextualKeyword["_abstract"] = 1] = "_abstract";
    ContextualKeyword[ContextualKeyword["_accessor"] = 2] = "_accessor";
    ContextualKeyword[ContextualKeyword["_as"] = 3] = "_as";
    ContextualKeyword[ContextualKeyword["_assert"] = 4] = "_assert";
    ContextualKeyword[ContextualKeyword["_asserts"] = 5] = "_asserts";
    ContextualKeyword[ContextualKeyword["_async"] = 6] = "_async";
    ContextualKeyword[ContextualKeyword["_await"] = 7] = "_await";
    ContextualKeyword[ContextualKeyword["_checks"] = 8] = "_checks";
    ContextualKeyword[ContextualKeyword["_constructor"] = 9] = "_constructor";
    ContextualKeyword[ContextualKeyword["_declare"] = 10] = "_declare";
    ContextualKeyword[ContextualKeyword["_enum"] = 11] = "_enum";
    ContextualKeyword[ContextualKeyword["_exports"] = 12] = "_exports";
    ContextualKeyword[ContextualKeyword["_from"] = 13] = "_from";
    ContextualKeyword[ContextualKeyword["_get"] = 14] = "_get";
    ContextualKeyword[ContextualKeyword["_global"] = 15] = "_global";
    ContextualKeyword[ContextualKeyword["_implements"] = 16] = "_implements";
    ContextualKeyword[ContextualKeyword["_infer"] = 17] = "_infer";
    ContextualKeyword[ContextualKeyword["_interface"] = 18] = "_interface";
    ContextualKeyword[ContextualKeyword["_is"] = 19] = "_is";
    ContextualKeyword[ContextualKeyword["_keyof"] = 20] = "_keyof";
    ContextualKeyword[ContextualKeyword["_mixins"] = 21] = "_mixins";
    ContextualKeyword[ContextualKeyword["_module"] = 22] = "_module";
    ContextualKeyword[ContextualKeyword["_namespace"] = 23] = "_namespace";
    ContextualKeyword[ContextualKeyword["_of"] = 24] = "_of";
    ContextualKeyword[ContextualKeyword["_opaque"] = 25] = "_opaque";
    ContextualKeyword[ContextualKeyword["_out"] = 26] = "_out";
    ContextualKeyword[ContextualKeyword["_override"] = 27] = "_override";
    ContextualKeyword[ContextualKeyword["_private"] = 28] = "_private";
    ContextualKeyword[ContextualKeyword["_protected"] = 29] = "_protected";
    ContextualKeyword[ContextualKeyword["_proto"] = 30] = "_proto";
    ContextualKeyword[ContextualKeyword["_public"] = 31] = "_public";
    ContextualKeyword[ContextualKeyword["_readonly"] = 32] = "_readonly";
    ContextualKeyword[ContextualKeyword["_require"] = 33] = "_require";
    ContextualKeyword[ContextualKeyword["_satisfies"] = 34] = "_satisfies";
    ContextualKeyword[ContextualKeyword["_set"] = 35] = "_set";
    ContextualKeyword[ContextualKeyword["_static"] = 36] = "_static";
    ContextualKeyword[ContextualKeyword["_symbol"] = 37] = "_symbol";
    ContextualKeyword[ContextualKeyword["_type"] = 38] = "_type";
    ContextualKeyword[ContextualKeyword["_unique"] = 39] = "_unique";
    ContextualKeyword[ContextualKeyword["_using"] = 40] = "_using";
})(ContextualKeyword || (ContextualKeyword = {}));

// Generated file, do not edit! Run "yarn generate" to re-generate this file.
/* istanbul ignore file */
/**
 * Enum of all token types, with bit fields to signify meaningful properties.
 */
var TokenType;
(function (TokenType) {
    // Precedence 0 means not an operator; otherwise it is a positive number up to 12.
    TokenType[TokenType["PRECEDENCE_MASK"] = 15] = "PRECEDENCE_MASK";
    TokenType[TokenType["IS_KEYWORD"] = 16] = "IS_KEYWORD";
    TokenType[TokenType["IS_ASSIGN"] = 32] = "IS_ASSIGN";
    TokenType[TokenType["IS_RIGHT_ASSOCIATIVE"] = 64] = "IS_RIGHT_ASSOCIATIVE";
    TokenType[TokenType["IS_PREFIX"] = 128] = "IS_PREFIX";
    TokenType[TokenType["IS_POSTFIX"] = 256] = "IS_POSTFIX";
    TokenType[TokenType["IS_EXPRESSION_START"] = 512] = "IS_EXPRESSION_START";
    TokenType[TokenType["num"] = 512] = "num";
    TokenType[TokenType["bigint"] = 1536] = "bigint";
    TokenType[TokenType["decimal"] = 2560] = "decimal";
    TokenType[TokenType["regexp"] = 3584] = "regexp";
    TokenType[TokenType["string"] = 4608] = "string";
    TokenType[TokenType["name"] = 5632] = "name";
    TokenType[TokenType["eof"] = 6144] = "eof";
    TokenType[TokenType["bracketL"] = 7680] = "bracketL";
    TokenType[TokenType["bracketR"] = 8192] = "bracketR";
    TokenType[TokenType["braceL"] = 9728] = "braceL";
    TokenType[TokenType["braceBarL"] = 10752] = "braceBarL";
    TokenType[TokenType["braceR"] = 11264] = "braceR";
    TokenType[TokenType["braceBarR"] = 12288] = "braceBarR";
    TokenType[TokenType["parenL"] = 13824] = "parenL";
    TokenType[TokenType["parenR"] = 14336] = "parenR";
    TokenType[TokenType["comma"] = 15360] = "comma";
    TokenType[TokenType["semi"] = 16384] = "semi";
    TokenType[TokenType["colon"] = 17408] = "colon";
    TokenType[TokenType["doubleColon"] = 18432] = "doubleColon";
    TokenType[TokenType["dot"] = 19456] = "dot";
    TokenType[TokenType["question"] = 20480] = "question";
    TokenType[TokenType["questionDot"] = 21504] = "questionDot";
    TokenType[TokenType["arrow"] = 22528] = "arrow";
    TokenType[TokenType["template"] = 23552] = "template";
    TokenType[TokenType["ellipsis"] = 24576] = "ellipsis";
    TokenType[TokenType["backQuote"] = 25600] = "backQuote";
    TokenType[TokenType["dollarBraceL"] = 27136] = "dollarBraceL";
    TokenType[TokenType["at"] = 27648] = "at";
    TokenType[TokenType["hash"] = 29184] = "hash";
    TokenType[TokenType["eq"] = 29728] = "eq";
    TokenType[TokenType["assign"] = 30752] = "assign";
    TokenType[TokenType["preIncDec"] = 32640] = "preIncDec";
    TokenType[TokenType["postIncDec"] = 33664] = "postIncDec";
    TokenType[TokenType["bang"] = 34432] = "bang";
    TokenType[TokenType["tilde"] = 35456] = "tilde";
    TokenType[TokenType["pipeline"] = 35841] = "pipeline";
    TokenType[TokenType["nullishCoalescing"] = 36866] = "nullishCoalescing";
    TokenType[TokenType["logicalOR"] = 37890] = "logicalOR";
    TokenType[TokenType["logicalAND"] = 38915] = "logicalAND";
    TokenType[TokenType["bitwiseOR"] = 39940] = "bitwiseOR";
    TokenType[TokenType["bitwiseXOR"] = 40965] = "bitwiseXOR";
    TokenType[TokenType["bitwiseAND"] = 41990] = "bitwiseAND";
    TokenType[TokenType["equality"] = 43015] = "equality";
    TokenType[TokenType["lessThan"] = 44040] = "lessThan";
    TokenType[TokenType["greaterThan"] = 45064] = "greaterThan";
    TokenType[TokenType["relationalOrEqual"] = 46088] = "relationalOrEqual";
    TokenType[TokenType["bitShiftL"] = 47113] = "bitShiftL";
    TokenType[TokenType["bitShiftR"] = 48137] = "bitShiftR";
    TokenType[TokenType["plus"] = 49802] = "plus";
    TokenType[TokenType["minus"] = 50826] = "minus";
    TokenType[TokenType["modulo"] = 51723] = "modulo";
    TokenType[TokenType["star"] = 52235] = "star";
    TokenType[TokenType["slash"] = 53259] = "slash";
    TokenType[TokenType["exponent"] = 54348] = "exponent";
    TokenType[TokenType["jsxName"] = 55296] = "jsxName";
    TokenType[TokenType["jsxText"] = 56320] = "jsxText";
    TokenType[TokenType["jsxEmptyText"] = 57344] = "jsxEmptyText";
    TokenType[TokenType["jsxTagStart"] = 58880] = "jsxTagStart";
    TokenType[TokenType["jsxTagEnd"] = 59392] = "jsxTagEnd";
    TokenType[TokenType["typeParameterStart"] = 60928] = "typeParameterStart";
    TokenType[TokenType["nonNullAssertion"] = 61440] = "nonNullAssertion";
    TokenType[TokenType["_break"] = 62480] = "_break";
    TokenType[TokenType["_case"] = 63504] = "_case";
    TokenType[TokenType["_catch"] = 64528] = "_catch";
    TokenType[TokenType["_continue"] = 65552] = "_continue";
    TokenType[TokenType["_debugger"] = 66576] = "_debugger";
    TokenType[TokenType["_default"] = 67600] = "_default";
    TokenType[TokenType["_do"] = 68624] = "_do";
    TokenType[TokenType["_else"] = 69648] = "_else";
    TokenType[TokenType["_finally"] = 70672] = "_finally";
    TokenType[TokenType["_for"] = 71696] = "_for";
    TokenType[TokenType["_function"] = 73232] = "_function";
    TokenType[TokenType["_if"] = 73744] = "_if";
    TokenType[TokenType["_return"] = 74768] = "_return";
    TokenType[TokenType["_switch"] = 75792] = "_switch";
    TokenType[TokenType["_throw"] = 77456] = "_throw";
    TokenType[TokenType["_try"] = 77840] = "_try";
    TokenType[TokenType["_var"] = 78864] = "_var";
    TokenType[TokenType["_let"] = 79888] = "_let";
    TokenType[TokenType["_const"] = 80912] = "_const";
    TokenType[TokenType["_while"] = 81936] = "_while";
    TokenType[TokenType["_with"] = 82960] = "_with";
    TokenType[TokenType["_new"] = 84496] = "_new";
    TokenType[TokenType["_this"] = 85520] = "_this";
    TokenType[TokenType["_super"] = 86544] = "_super";
    TokenType[TokenType["_class"] = 87568] = "_class";
    TokenType[TokenType["_extends"] = 88080] = "_extends";
    TokenType[TokenType["_export"] = 89104] = "_export";
    TokenType[TokenType["_import"] = 90640] = "_import";
    TokenType[TokenType["_yield"] = 91664] = "_yield";
    TokenType[TokenType["_null"] = 92688] = "_null";
    TokenType[TokenType["_true"] = 93712] = "_true";
    TokenType[TokenType["_false"] = 94736] = "_false";
    TokenType[TokenType["_in"] = 95256] = "_in";
    TokenType[TokenType["_instanceof"] = 96280] = "_instanceof";
    TokenType[TokenType["_typeof"] = 97936] = "_typeof";
    TokenType[TokenType["_void"] = 98960] = "_void";
    TokenType[TokenType["_delete"] = 99984] = "_delete";
    TokenType[TokenType["_async"] = 100880] = "_async";
    TokenType[TokenType["_get"] = 101904] = "_get";
    TokenType[TokenType["_set"] = 102928] = "_set";
    TokenType[TokenType["_declare"] = 103952] = "_declare";
    TokenType[TokenType["_readonly"] = 104976] = "_readonly";
    TokenType[TokenType["_abstract"] = 106000] = "_abstract";
    TokenType[TokenType["_static"] = 107024] = "_static";
    TokenType[TokenType["_public"] = 107536] = "_public";
    TokenType[TokenType["_private"] = 108560] = "_private";
    TokenType[TokenType["_protected"] = 109584] = "_protected";
    TokenType[TokenType["_override"] = 110608] = "_override";
    TokenType[TokenType["_as"] = 112144] = "_as";
    TokenType[TokenType["_enum"] = 113168] = "_enum";
    TokenType[TokenType["_type"] = 114192] = "_type";
    TokenType[TokenType["_implements"] = 115216] = "_implements";
})(TokenType || (TokenType = {}));
function formatTokenType(tokenType) {
    switch (tokenType) {
        case TokenType.num:
            return "num";
        case TokenType.bigint:
            return "bigint";
        case TokenType.decimal:
            return "decimal";
        case TokenType.regexp:
            return "regexp";
        case TokenType.string:
            return "string";
        case TokenType.name:
            return "name";
        case TokenType.eof:
            return "eof";
        case TokenType.bracketL:
            return "[";
        case TokenType.bracketR:
            return "]";
        case TokenType.braceL:
            return "{";
        case TokenType.braceBarL:
            return "{|";
        case TokenType.braceR:
            return "}";
        case TokenType.braceBarR:
            return "|}";
        case TokenType.parenL:
            return "(";
        case TokenType.parenR:
            return ")";
        case TokenType.comma:
            return ",";
        case TokenType.semi:
            return ";";
        case TokenType.colon:
            return ":";
        case TokenType.doubleColon:
            return "::";
        case TokenType.dot:
            return ".";
        case TokenType.question:
            return "?";
        case TokenType.questionDot:
            return "?.";
        case TokenType.arrow:
            return "=>";
        case TokenType.template:
            return "template";
        case TokenType.ellipsis:
            return "...";
        case TokenType.backQuote:
            return "`";
        case TokenType.dollarBraceL:
            return "${";
        case TokenType.at:
            return "@";
        case TokenType.hash:
            return "#";
        case TokenType.eq:
            return "=";
        case TokenType.assign:
            return "_=";
        case TokenType.preIncDec:
            return "++/--";
        case TokenType.postIncDec:
            return "++/--";
        case TokenType.bang:
            return "!";
        case TokenType.tilde:
            return "~";
        case TokenType.pipeline:
            return "|>";
        case TokenType.nullishCoalescing:
            return "??";
        case TokenType.logicalOR:
            return "||";
        case TokenType.logicalAND:
            return "&&";
        case TokenType.bitwiseOR:
            return "|";
        case TokenType.bitwiseXOR:
            return "^";
        case TokenType.bitwiseAND:
            return "&";
        case TokenType.equality:
            return "==/!=";
        case TokenType.lessThan:
            return "<";
        case TokenType.greaterThan:
            return ">";
        case TokenType.relationalOrEqual:
            return "<=/>=";
        case TokenType.bitShiftL:
            return "<<";
        case TokenType.bitShiftR:
            return ">>/>>>";
        case TokenType.plus:
            return "+";
        case TokenType.minus:
            return "-";
        case TokenType.modulo:
            return "%";
        case TokenType.star:
            return "*";
        case TokenType.slash:
            return "/";
        case TokenType.exponent:
            return "**";
        case TokenType.jsxName:
            return "jsxName";
        case TokenType.jsxText:
            return "jsxText";
        case TokenType.jsxEmptyText:
            return "jsxEmptyText";
        case TokenType.jsxTagStart:
            return "jsxTagStart";
        case TokenType.jsxTagEnd:
            return "jsxTagEnd";
        case TokenType.typeParameterStart:
            return "typeParameterStart";
        case TokenType.nonNullAssertion:
            return "nonNullAssertion";
        case TokenType._break:
            return "break";
        case TokenType._case:
            return "case";
        case TokenType._catch:
            return "catch";
        case TokenType._continue:
            return "continue";
        case TokenType._debugger:
            return "debugger";
        case TokenType._default:
            return "default";
        case TokenType._do:
            return "do";
        case TokenType._else:
            return "else";
        case TokenType._finally:
            return "finally";
        case TokenType._for:
            return "for";
        case TokenType._function:
            return "function";
        case TokenType._if:
            return "if";
        case TokenType._return:
            return "return";
        case TokenType._switch:
            return "switch";
        case TokenType._throw:
            return "throw";
        case TokenType._try:
            return "try";
        case TokenType._var:
            return "var";
        case TokenType._let:
            return "let";
        case TokenType._const:
            return "const";
        case TokenType._while:
            return "while";
        case TokenType._with:
            return "with";
        case TokenType._new:
            return "new";
        case TokenType._this:
            return "this";
        case TokenType._super:
            return "super";
        case TokenType._class:
            return "class";
        case TokenType._extends:
            return "extends";
        case TokenType._export:
            return "export";
        case TokenType._import:
            return "import";
        case TokenType._yield:
            return "yield";
        case TokenType._null:
            return "null";
        case TokenType._true:
            return "true";
        case TokenType._false:
            return "false";
        case TokenType._in:
            return "in";
        case TokenType._instanceof:
            return "instanceof";
        case TokenType._typeof:
            return "typeof";
        case TokenType._void:
            return "void";
        case TokenType._delete:
            return "delete";
        case TokenType._async:
            return "async";
        case TokenType._get:
            return "get";
        case TokenType._set:
            return "set";
        case TokenType._declare:
            return "declare";
        case TokenType._readonly:
            return "readonly";
        case TokenType._abstract:
            return "abstract";
        case TokenType._static:
            return "static";
        case TokenType._public:
            return "public";
        case TokenType._private:
            return "private";
        case TokenType._protected:
            return "protected";
        case TokenType._override:
            return "override";
        case TokenType._as:
            return "as";
        case TokenType._enum:
            return "enum";
        case TokenType._type:
            return "type";
        case TokenType._implements:
            return "implements";
        default:
            return "";
    }
}

class Scope {
    startTokenIndex;
    endTokenIndex;
    isFunctionScope;
    constructor(startTokenIndex, endTokenIndex, isFunctionScope) {
        this.startTokenIndex = startTokenIndex;
        this.endTokenIndex = endTokenIndex;
        this.isFunctionScope = isFunctionScope;
    }
}
class StateSnapshot {
    potentialArrowAt;
    noAnonFunctionType;
    inDisallowConditionalTypesContext;
    tokensLength;
    scopesLength;
    pos;
    type;
    contextualKeyword;
    start;
    end;
    isType;
    scopeDepth;
    error;
    constructor(potentialArrowAt, noAnonFunctionType, inDisallowConditionalTypesContext, tokensLength, scopesLength, pos, type, contextualKeyword, start, end, isType, scopeDepth, error) {
        this.potentialArrowAt = potentialArrowAt;
        this.noAnonFunctionType = noAnonFunctionType;
        this.inDisallowConditionalTypesContext = inDisallowConditionalTypesContext;
        this.tokensLength = tokensLength;
        this.scopesLength = scopesLength;
        this.pos = pos;
        this.type = type;
        this.contextualKeyword = contextualKeyword;
        this.start = start;
        this.end = end;
        this.isType = isType;
        this.scopeDepth = scopeDepth;
        this.error = error;
    }
}
class State {
    // Used to signify the start of a potential arrow function
    potentialArrowAt = -1;
    // Used by Flow to handle an edge case involving function type parsing.
    noAnonFunctionType = false;
    // Used by TypeScript to handle ambiguities when parsing conditional types.
    inDisallowConditionalTypesContext = false;
    // Token store.
    tokens = [];
    // Array of all observed scopes, ordered by their ending position.
    scopes = [];
    // The current position of the tokenizer in the input.
    pos = 0;
    // Information about the current token.
    type = TokenType.eof;
    contextualKeyword = ContextualKeyword.NONE;
    start = 0;
    end = 0;
    isType = false;
    scopeDepth = 0;
    /**
     * If the parser is in an error state, then the token is always tt.eof and all functions can
     * keep executing but should be written so they don't get into an infinite loop in this situation.
     *
     * This approach, combined with the ability to snapshot and restore state, allows us to implement
     * backtracking without exceptions and without needing to explicitly propagate error states
     * everywhere.
     */
    error = null;
    snapshot() {
        return new StateSnapshot(this.potentialArrowAt, this.noAnonFunctionType, this.inDisallowConditionalTypesContext, this.tokens.length, this.scopes.length, this.pos, this.type, this.contextualKeyword, this.start, this.end, this.isType, this.scopeDepth, this.error);
    }
    restoreFromSnapshot(snapshot) {
        this.potentialArrowAt = snapshot.potentialArrowAt;
        this.noAnonFunctionType = snapshot.noAnonFunctionType;
        this.inDisallowConditionalTypesContext = snapshot.inDisallowConditionalTypesContext;
        this.tokens.length = snapshot.tokensLength;
        this.scopes.length = snapshot.scopesLength;
        this.pos = snapshot.pos;
        this.type = snapshot.type;
        this.contextualKeyword = snapshot.contextualKeyword;
        this.start = snapshot.start;
        this.end = snapshot.end;
        this.isType = snapshot.isType;
        this.scopeDepth = snapshot.scopeDepth;
        this.error = snapshot.error;
    }
}

var charCodes;
(function (charCodes) {
    charCodes[charCodes["backSpace"] = 8] = "backSpace";
    charCodes[charCodes["lineFeed"] = 10] = "lineFeed";
    charCodes[charCodes["tab"] = 9] = "tab";
    charCodes[charCodes["carriageReturn"] = 13] = "carriageReturn";
    charCodes[charCodes["shiftOut"] = 14] = "shiftOut";
    charCodes[charCodes["space"] = 32] = "space";
    charCodes[charCodes["exclamationMark"] = 33] = "exclamationMark";
    charCodes[charCodes["quotationMark"] = 34] = "quotationMark";
    charCodes[charCodes["numberSign"] = 35] = "numberSign";
    charCodes[charCodes["dollarSign"] = 36] = "dollarSign";
    charCodes[charCodes["percentSign"] = 37] = "percentSign";
    charCodes[charCodes["ampersand"] = 38] = "ampersand";
    charCodes[charCodes["apostrophe"] = 39] = "apostrophe";
    charCodes[charCodes["leftParenthesis"] = 40] = "leftParenthesis";
    charCodes[charCodes["rightParenthesis"] = 41] = "rightParenthesis";
    charCodes[charCodes["asterisk"] = 42] = "asterisk";
    charCodes[charCodes["plusSign"] = 43] = "plusSign";
    charCodes[charCodes["comma"] = 44] = "comma";
    charCodes[charCodes["dash"] = 45] = "dash";
    charCodes[charCodes["dot"] = 46] = "dot";
    charCodes[charCodes["slash"] = 47] = "slash";
    charCodes[charCodes["digit0"] = 48] = "digit0";
    charCodes[charCodes["digit1"] = 49] = "digit1";
    charCodes[charCodes["digit2"] = 50] = "digit2";
    charCodes[charCodes["digit3"] = 51] = "digit3";
    charCodes[charCodes["digit4"] = 52] = "digit4";
    charCodes[charCodes["digit5"] = 53] = "digit5";
    charCodes[charCodes["digit6"] = 54] = "digit6";
    charCodes[charCodes["digit7"] = 55] = "digit7";
    charCodes[charCodes["digit8"] = 56] = "digit8";
    charCodes[charCodes["digit9"] = 57] = "digit9";
    charCodes[charCodes["colon"] = 58] = "colon";
    charCodes[charCodes["semicolon"] = 59] = "semicolon";
    charCodes[charCodes["lessThan"] = 60] = "lessThan";
    charCodes[charCodes["equalsTo"] = 61] = "equalsTo";
    charCodes[charCodes["greaterThan"] = 62] = "greaterThan";
    charCodes[charCodes["questionMark"] = 63] = "questionMark";
    charCodes[charCodes["atSign"] = 64] = "atSign";
    charCodes[charCodes["uppercaseA"] = 65] = "uppercaseA";
    charCodes[charCodes["uppercaseB"] = 66] = "uppercaseB";
    charCodes[charCodes["uppercaseC"] = 67] = "uppercaseC";
    charCodes[charCodes["uppercaseD"] = 68] = "uppercaseD";
    charCodes[charCodes["uppercaseE"] = 69] = "uppercaseE";
    charCodes[charCodes["uppercaseF"] = 70] = "uppercaseF";
    charCodes[charCodes["uppercaseG"] = 71] = "uppercaseG";
    charCodes[charCodes["uppercaseH"] = 72] = "uppercaseH";
    charCodes[charCodes["uppercaseI"] = 73] = "uppercaseI";
    charCodes[charCodes["uppercaseJ"] = 74] = "uppercaseJ";
    charCodes[charCodes["uppercaseK"] = 75] = "uppercaseK";
    charCodes[charCodes["uppercaseL"] = 76] = "uppercaseL";
    charCodes[charCodes["uppercaseM"] = 77] = "uppercaseM";
    charCodes[charCodes["uppercaseN"] = 78] = "uppercaseN";
    charCodes[charCodes["uppercaseO"] = 79] = "uppercaseO";
    charCodes[charCodes["uppercaseP"] = 80] = "uppercaseP";
    charCodes[charCodes["uppercaseQ"] = 81] = "uppercaseQ";
    charCodes[charCodes["uppercaseR"] = 82] = "uppercaseR";
    charCodes[charCodes["uppercaseS"] = 83] = "uppercaseS";
    charCodes[charCodes["uppercaseT"] = 84] = "uppercaseT";
    charCodes[charCodes["uppercaseU"] = 85] = "uppercaseU";
    charCodes[charCodes["uppercaseV"] = 86] = "uppercaseV";
    charCodes[charCodes["uppercaseW"] = 87] = "uppercaseW";
    charCodes[charCodes["uppercaseX"] = 88] = "uppercaseX";
    charCodes[charCodes["uppercaseY"] = 89] = "uppercaseY";
    charCodes[charCodes["uppercaseZ"] = 90] = "uppercaseZ";
    charCodes[charCodes["leftSquareBracket"] = 91] = "leftSquareBracket";
    charCodes[charCodes["backslash"] = 92] = "backslash";
    charCodes[charCodes["rightSquareBracket"] = 93] = "rightSquareBracket";
    charCodes[charCodes["caret"] = 94] = "caret";
    charCodes[charCodes["underscore"] = 95] = "underscore";
    charCodes[charCodes["graveAccent"] = 96] = "graveAccent";
    charCodes[charCodes["lowercaseA"] = 97] = "lowercaseA";
    charCodes[charCodes["lowercaseB"] = 98] = "lowercaseB";
    charCodes[charCodes["lowercaseC"] = 99] = "lowercaseC";
    charCodes[charCodes["lowercaseD"] = 100] = "lowercaseD";
    charCodes[charCodes["lowercaseE"] = 101] = "lowercaseE";
    charCodes[charCodes["lowercaseF"] = 102] = "lowercaseF";
    charCodes[charCodes["lowercaseG"] = 103] = "lowercaseG";
    charCodes[charCodes["lowercaseH"] = 104] = "lowercaseH";
    charCodes[charCodes["lowercaseI"] = 105] = "lowercaseI";
    charCodes[charCodes["lowercaseJ"] = 106] = "lowercaseJ";
    charCodes[charCodes["lowercaseK"] = 107] = "lowercaseK";
    charCodes[charCodes["lowercaseL"] = 108] = "lowercaseL";
    charCodes[charCodes["lowercaseM"] = 109] = "lowercaseM";
    charCodes[charCodes["lowercaseN"] = 110] = "lowercaseN";
    charCodes[charCodes["lowercaseO"] = 111] = "lowercaseO";
    charCodes[charCodes["lowercaseP"] = 112] = "lowercaseP";
    charCodes[charCodes["lowercaseQ"] = 113] = "lowercaseQ";
    charCodes[charCodes["lowercaseR"] = 114] = "lowercaseR";
    charCodes[charCodes["lowercaseS"] = 115] = "lowercaseS";
    charCodes[charCodes["lowercaseT"] = 116] = "lowercaseT";
    charCodes[charCodes["lowercaseU"] = 117] = "lowercaseU";
    charCodes[charCodes["lowercaseV"] = 118] = "lowercaseV";
    charCodes[charCodes["lowercaseW"] = 119] = "lowercaseW";
    charCodes[charCodes["lowercaseX"] = 120] = "lowercaseX";
    charCodes[charCodes["lowercaseY"] = 121] = "lowercaseY";
    charCodes[charCodes["lowercaseZ"] = 122] = "lowercaseZ";
    charCodes[charCodes["leftCurlyBrace"] = 123] = "leftCurlyBrace";
    charCodes[charCodes["verticalBar"] = 124] = "verticalBar";
    charCodes[charCodes["rightCurlyBrace"] = 125] = "rightCurlyBrace";
    charCodes[charCodes["tilde"] = 126] = "tilde";
    charCodes[charCodes["nonBreakingSpace"] = 160] = "nonBreakingSpace";
    // eslint-disable-next-line no-irregular-whitespace
    charCodes[charCodes["oghamSpaceMark"] = 5760] = "oghamSpaceMark";
    charCodes[charCodes["lineSeparator"] = 8232] = "lineSeparator";
    charCodes[charCodes["paragraphSeparator"] = 8233] = "paragraphSeparator";
})(charCodes || (charCodes = {}));

let isJSXEnabled;
let isTypeScriptEnabled;
let isFlowEnabled;
let state;
let input;
let nextContextId;
function getNextContextId() {
    return nextContextId++;
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function augmentError(error) {
    if ("pos" in error) {
        const loc = locationForIndex(error.pos);
        error.message += ` (${loc.line}:${loc.column})`;
        error.loc = loc;
    }
    return error;
}
class Loc {
    line;
    column;
    constructor(line, column) {
        this.line = line;
        this.column = column;
    }
}
function locationForIndex(pos) {
    let line = 1;
    let column = 1;
    for (let i = 0; i < pos; i++) {
        if (input.charCodeAt(i) === charCodes.lineFeed) {
            line++;
            column = 1;
        }
        else {
            column++;
        }
    }
    return new Loc(line, column);
}
function initParser(inputCode, isJSXEnabledArg, isTypeScriptEnabledArg, isFlowEnabledArg) {
    input = inputCode;
    state = new State();
    nextContextId = 1;
    isJSXEnabled = isJSXEnabledArg;
    isTypeScriptEnabled = isTypeScriptEnabledArg;
    isFlowEnabled = isFlowEnabledArg;
}

// ## Parser utilities
// Tests whether parsed token is a contextual keyword.
function isContextual(contextualKeyword) {
    return state.contextualKeyword === contextualKeyword;
}
function isLookaheadContextual(contextualKeyword) {
    const l = lookaheadTypeAndKeyword();
    return l.type === TokenType.name && l.contextualKeyword === contextualKeyword;
}
// Consumes contextual keyword if possible.
function eatContextual(contextualKeyword) {
    return state.contextualKeyword === contextualKeyword && eat(TokenType.name);
}
// Asserts that following token is given contextual keyword.
function expectContextual(contextualKeyword) {
    if (!eatContextual(contextualKeyword)) {
        unexpected();
    }
}
// Test whether a semicolon can be inserted at the current position.
function canInsertSemicolon() {
    return match(TokenType.eof) || match(TokenType.braceR) || hasPrecedingLineBreak();
}
function hasPrecedingLineBreak() {
    const prevToken = state.tokens[state.tokens.length - 1];
    const lastTokEnd = prevToken ? prevToken.end : 0;
    for (let i = lastTokEnd; i < state.start; i++) {
        const code = input.charCodeAt(i);
        if (code === charCodes.lineFeed ||
            code === charCodes.carriageReturn ||
            code === 0x2028 ||
            code === 0x2029) {
            return true;
        }
    }
    return false;
}
function hasFollowingLineBreak() {
    const nextStart = nextTokenStart();
    for (let i = state.end; i < nextStart; i++) {
        const code = input.charCodeAt(i);
        if (code === charCodes.lineFeed ||
            code === charCodes.carriageReturn ||
            code === 0x2028 ||
            code === 0x2029) {
            return true;
        }
    }
    return false;
}
function isLineTerminator() {
    return eat(TokenType.semi) || canInsertSemicolon();
}
// Consume a semicolon, or, failing that, see if we are allowed to
// pretend that there is a semicolon at this position.
function semicolon() {
    if (!isLineTerminator()) {
        unexpected('Unexpected token, expected ";"');
    }
}
// Expect a token of a given type. If found, consume it, otherwise,
// raise an unexpected token error at given pos.
function expect(type) {
    const matched = eat(type);
    if (!matched) {
        unexpected(`Unexpected token, expected "${formatTokenType(type)}"`);
    }
}
/**
 * Transition the parser to an error state. All code needs to be written to naturally unwind in this
 * state, which allows us to backtrack without exceptions and without error plumbing everywhere.
 */
function unexpected(message = "Unexpected token", pos = state.start) {
    if (state.error) {
        return;
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const err = new SyntaxError(message);
    err.pos = pos;
    state.error = err;
    state.pos = input.length;
    finishToken(TokenType.eof);
}

// https://tc39.github.io/ecma262/#sec-white-space
const WHITESPACE_CHARS = [
    0x0009,
    0x000b,
    0x000c,
    charCodes.space,
    charCodes.nonBreakingSpace,
    charCodes.oghamSpaceMark,
    0x2000, // EN QUAD
    0x2001, // EM QUAD
    0x2002, // EN SPACE
    0x2003, // EM SPACE
    0x2004, // THREE-PER-EM SPACE
    0x2005, // FOUR-PER-EM SPACE
    0x2006, // SIX-PER-EM SPACE
    0x2007, // FIGURE SPACE
    0x2008, // PUNCTUATION SPACE
    0x2009, // THIN SPACE
    0x200a, // HAIR SPACE
    0x202f, // NARROW NO-BREAK SPACE
    0x205f, // MEDIUM MATHEMATICAL SPACE
    0x3000, // IDEOGRAPHIC SPACE
    0xfeff, // ZERO WIDTH NO-BREAK SPACE
];
const skipWhiteSpace = /(?:\s|\/\/.*|\/\*[^]*?\*\/)*/g;
const IS_WHITESPACE = new Uint8Array(65536);
for (const char of WHITESPACE_CHARS) {
    IS_WHITESPACE[char] = 1;
}

function computeIsIdentifierChar(code) {
    if (code < 48)
        return code === 36;
    if (code < 58)
        return true;
    if (code < 65)
        return false;
    if (code < 91)
        return true;
    if (code < 97)
        return code === 95;
    if (code < 123)
        return true;
    if (code < 128)
        return false;
    throw new Error("Should not be called with non-ASCII char code.");
}
const IS_IDENTIFIER_CHAR = new Uint8Array(65536);
for (let i = 0; i < 128; i++) {
    IS_IDENTIFIER_CHAR[i] = computeIsIdentifierChar(i) ? 1 : 0;
}
for (let i = 128; i < 65536; i++) {
    IS_IDENTIFIER_CHAR[i] = 1;
}
// Aside from whitespace and newlines, all characters outside the ASCII space are either
// identifier characters or invalid. Since we're not performing code validation, we can just
// treat all invalid characters as identifier characters.
for (const whitespaceChar of WHITESPACE_CHARS) {
    IS_IDENTIFIER_CHAR[whitespaceChar] = 0;
}
IS_IDENTIFIER_CHAR[0x2028] = 0;
IS_IDENTIFIER_CHAR[0x2029] = 0;
const IS_IDENTIFIER_START = IS_IDENTIFIER_CHAR.slice();
for (let numChar = charCodes.digit0; numChar <= charCodes.digit9; numChar++) {
    IS_IDENTIFIER_START[numChar] = 0;
}

// Generated file, do not edit! Run "yarn generate" to re-generate this file.
// prettier-ignore
const READ_WORD_TREE = new Int32Array([
    // ""
    -1, 27, 783, 918, 1755, 2376, 2862, 3483, -1, 3699, -1, 4617, 4752, 4833, 5130, 5508, 5940, -1, 6480, 6939, 7749, 8181, 8451, 8613, -1, 8829, -1,
    // "a"
    -1, -1, 54, 243, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 432, -1, -1, -1, 675, -1, -1, -1,
    // "ab"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 81, -1, -1, -1, -1, -1, -1, -1,
    // "abs"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 108, -1, -1, -1, -1, -1, -1,
    // "abst"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 135, -1, -1, -1, -1, -1, -1, -1, -1,
    // "abstr"
    -1, 162, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "abstra"
    -1, -1, -1, 189, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "abstrac"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 216, -1, -1, -1, -1, -1, -1,
    // "abstract"
    ContextualKeyword._abstract << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "ac"
    -1, -1, -1, 270, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "acc"
    -1, -1, -1, -1, -1, 297, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "acce"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 324, -1, -1, -1, -1, -1, -1, -1,
    // "acces"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 351, -1, -1, -1, -1, -1, -1, -1,
    // "access"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 378, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "accesso"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 405, -1, -1, -1, -1, -1, -1, -1, -1,
    // "accessor"
    ContextualKeyword._accessor << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "as"
    ContextualKeyword._as << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 459, -1, -1, -1, -1, -1, 594, -1,
    // "ass"
    -1, -1, -1, -1, -1, 486, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "asse"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 513, -1, -1, -1, -1, -1, -1, -1, -1,
    // "asser"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 540, -1, -1, -1, -1, -1, -1,
    // "assert"
    ContextualKeyword._assert << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 567, -1, -1, -1, -1, -1, -1, -1,
    // "asserts"
    ContextualKeyword._asserts << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "asy"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 621, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "asyn"
    -1, -1, -1, 648, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "async"
    ContextualKeyword._async << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "aw"
    -1, 702, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "awa"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, 729, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "awai"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 756, -1, -1, -1, -1, -1, -1,
    // "await"
    ContextualKeyword._await << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "b"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 810, -1, -1, -1, -1, -1, -1, -1, -1,
    // "br"
    -1, -1, -1, -1, -1, 837, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "bre"
    -1, 864, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "brea"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 891, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "break"
    (TokenType._break << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "c"
    -1, 945, -1, -1, -1, -1, -1, -1, 1107, -1, -1, -1, 1242, -1, -1, 1350, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "ca"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 972, 1026, -1, -1, -1, -1, -1, -1,
    // "cas"
    -1, -1, -1, -1, -1, 999, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "case"
    (TokenType._case << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "cat"
    -1, -1, -1, 1053, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "catc"
    -1, -1, -1, -1, -1, -1, -1, -1, 1080, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "catch"
    (TokenType._catch << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "ch"
    -1, -1, -1, -1, -1, 1134, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "che"
    -1, -1, -1, 1161, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "chec"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1188, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "check"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1215, -1, -1, -1, -1, -1, -1, -1,
    // "checks"
    ContextualKeyword._checks << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "cl"
    -1, 1269, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "cla"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1296, -1, -1, -1, -1, -1, -1, -1,
    // "clas"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1323, -1, -1, -1, -1, -1, -1, -1,
    // "class"
    (TokenType._class << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "co"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1377, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "con"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1404, 1620, -1, -1, -1, -1, -1, -1,
    // "cons"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1431, -1, -1, -1, -1, -1, -1,
    // "const"
    (TokenType._const << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1458, -1, -1, -1, -1, -1, -1, -1, -1,
    // "constr"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1485, -1, -1, -1, -1, -1,
    // "constru"
    -1, -1, -1, 1512, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "construc"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1539, -1, -1, -1, -1, -1, -1,
    // "construct"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1566, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "constructo"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1593, -1, -1, -1, -1, -1, -1, -1, -1,
    // "constructor"
    ContextualKeyword._constructor << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "cont"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, 1647, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "conti"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1674, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "contin"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1701, -1, -1, -1, -1, -1,
    // "continu"
    -1, -1, -1, -1, -1, 1728, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "continue"
    (TokenType._continue << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "d"
    -1, -1, -1, -1, -1, 1782, -1, -1, -1, -1, -1, -1, -1, -1, -1, 2349, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "de"
    -1, -1, 1809, 1971, -1, -1, 2106, -1, -1, -1, -1, -1, 2241, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "deb"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1836, -1, -1, -1, -1, -1,
    // "debu"
    -1, -1, -1, -1, -1, -1, -1, 1863, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "debug"
    -1, -1, -1, -1, -1, -1, -1, 1890, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "debugg"
    -1, -1, -1, -1, -1, 1917, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "debugge"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1944, -1, -1, -1, -1, -1, -1, -1, -1,
    // "debugger"
    (TokenType._debugger << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "dec"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1998, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "decl"
    -1, 2025, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "decla"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 2052, -1, -1, -1, -1, -1, -1, -1, -1,
    // "declar"
    -1, -1, -1, -1, -1, 2079, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "declare"
    ContextualKeyword._declare << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "def"
    -1, 2133, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "defa"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 2160, -1, -1, -1, -1, -1,
    // "defau"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 2187, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "defaul"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 2214, -1, -1, -1, -1, -1, -1,
    // "default"
    (TokenType._default << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "del"
    -1, -1, -1, -1, -1, 2268, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "dele"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 2295, -1, -1, -1, -1, -1, -1,
    // "delet"
    -1, -1, -1, -1, -1, 2322, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "delete"
    (TokenType._delete << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "do"
    (TokenType._do << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "e"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 2403, -1, 2484, -1, -1, -1, -1, -1, -1, -1, -1, -1, 2565, -1, -1,
    // "el"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 2430, -1, -1, -1, -1, -1, -1, -1,
    // "els"
    -1, -1, -1, -1, -1, 2457, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "else"
    (TokenType._else << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "en"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 2511, -1, -1, -1, -1, -1,
    // "enu"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 2538, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "enum"
    ContextualKeyword._enum << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "ex"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 2592, -1, -1, -1, 2727, -1, -1, -1, -1, -1, -1,
    // "exp"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 2619, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "expo"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 2646, -1, -1, -1, -1, -1, -1, -1, -1,
    // "expor"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 2673, -1, -1, -1, -1, -1, -1,
    // "export"
    (TokenType._export << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 2700, -1, -1, -1, -1, -1, -1, -1,
    // "exports"
    ContextualKeyword._exports << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "ext"
    -1, -1, -1, -1, -1, 2754, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "exte"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 2781, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "exten"
    -1, -1, -1, -1, 2808, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "extend"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 2835, -1, -1, -1, -1, -1, -1, -1,
    // "extends"
    (TokenType._extends << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "f"
    -1, 2889, -1, -1, -1, -1, -1, -1, -1, 2997, -1, -1, -1, -1, -1, 3159, -1, -1, 3213, -1, -1, 3294, -1, -1, -1, -1, -1,
    // "fa"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 2916, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "fal"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 2943, -1, -1, -1, -1, -1, -1, -1,
    // "fals"
    -1, -1, -1, -1, -1, 2970, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "false"
    (TokenType._false << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "fi"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 3024, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "fin"
    -1, 3051, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "fina"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 3078, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "final"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 3105, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "finall"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 3132, -1,
    // "finally"
    (TokenType._finally << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "fo"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 3186, -1, -1, -1, -1, -1, -1, -1, -1,
    // "for"
    (TokenType._for << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "fr"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 3240, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "fro"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 3267, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "from"
    ContextualKeyword._from << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "fu"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 3321, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "fun"
    -1, -1, -1, 3348, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "func"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 3375, -1, -1, -1, -1, -1, -1,
    // "funct"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, 3402, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "functi"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 3429, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "functio"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 3456, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "function"
    (TokenType._function << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "g"
    -1, -1, -1, -1, -1, 3510, -1, -1, -1, -1, -1, -1, 3564, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "ge"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 3537, -1, -1, -1, -1, -1, -1,
    // "get"
    ContextualKeyword._get << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "gl"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 3591, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "glo"
    -1, -1, 3618, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "glob"
    -1, 3645, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "globa"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 3672, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "global"
    ContextualKeyword._global << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "i"
    -1, -1, -1, -1, -1, -1, 3726, -1, -1, -1, -1, -1, -1, 3753, 4077, -1, -1, -1, -1, 4590, -1, -1, -1, -1, -1, -1, -1,
    // "if"
    (TokenType._if << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "im"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 3780, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "imp"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 3807, -1, -1, 3996, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "impl"
    -1, -1, -1, -1, -1, 3834, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "imple"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 3861, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "implem"
    -1, -1, -1, -1, -1, 3888, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "impleme"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 3915, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "implemen"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 3942, -1, -1, -1, -1, -1, -1,
    // "implement"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 3969, -1, -1, -1, -1, -1, -1, -1,
    // "implements"
    ContextualKeyword._implements << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "impo"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 4023, -1, -1, -1, -1, -1, -1, -1, -1,
    // "impor"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 4050, -1, -1, -1, -1, -1, -1,
    // "import"
    (TokenType._import << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "in"
    (TokenType._in << 1) + 1, -1, -1, -1, -1, -1, 4104, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 4185, 4401, -1, -1, -1, -1, -1, -1,
    // "inf"
    -1, -1, -1, -1, -1, 4131, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "infe"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 4158, -1, -1, -1, -1, -1, -1, -1, -1,
    // "infer"
    ContextualKeyword._infer << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "ins"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 4212, -1, -1, -1, -1, -1, -1,
    // "inst"
    -1, 4239, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "insta"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 4266, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "instan"
    -1, -1, -1, 4293, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "instanc"
    -1, -1, -1, -1, -1, 4320, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "instance"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 4347, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "instanceo"
    -1, -1, -1, -1, -1, -1, 4374, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "instanceof"
    (TokenType._instanceof << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "int"
    -1, -1, -1, -1, -1, 4428, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "inte"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 4455, -1, -1, -1, -1, -1, -1, -1, -1,
    // "inter"
    -1, -1, -1, -1, -1, -1, 4482, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "interf"
    -1, 4509, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "interfa"
    -1, -1, -1, 4536, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "interfac"
    -1, -1, -1, -1, -1, 4563, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "interface"
    ContextualKeyword._interface << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "is"
    ContextualKeyword._is << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "k"
    -1, -1, -1, -1, -1, 4644, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "ke"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 4671, -1,
    // "key"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 4698, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "keyo"
    -1, -1, -1, -1, -1, -1, 4725, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "keyof"
    ContextualKeyword._keyof << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "l"
    -1, -1, -1, -1, -1, 4779, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "le"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 4806, -1, -1, -1, -1, -1, -1,
    // "let"
    (TokenType._let << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "m"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, 4860, -1, -1, -1, -1, -1, 4995, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "mi"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 4887, -1, -1,
    // "mix"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, 4914, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "mixi"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 4941, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "mixin"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 4968, -1, -1, -1, -1, -1, -1, -1,
    // "mixins"
    ContextualKeyword._mixins << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "mo"
    -1, -1, -1, -1, 5022, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "mod"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 5049, -1, -1, -1, -1, -1,
    // "modu"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 5076, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "modul"
    -1, -1, -1, -1, -1, 5103, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "module"
    ContextualKeyword._module << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "n"
    -1, 5157, -1, -1, -1, 5373, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 5427, -1, -1, -1, -1, -1,
    // "na"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 5184, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "nam"
    -1, -1, -1, -1, -1, 5211, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "name"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 5238, -1, -1, -1, -1, -1, -1, -1,
    // "names"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 5265, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "namesp"
    -1, 5292, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "namespa"
    -1, -1, -1, 5319, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "namespac"
    -1, -1, -1, -1, -1, 5346, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "namespace"
    ContextualKeyword._namespace << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "ne"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 5400, -1, -1, -1,
    // "new"
    (TokenType._new << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "nu"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 5454, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "nul"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 5481, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "null"
    (TokenType._null << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "o"
    -1, -1, -1, -1, -1, -1, 5535, -1, -1, -1, -1, -1, -1, -1, -1, -1, 5562, -1, -1, -1, -1, 5697, 5751, -1, -1, -1, -1,
    // "of"
    ContextualKeyword._of << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "op"
    -1, 5589, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "opa"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 5616, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "opaq"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 5643, -1, -1, -1, -1, -1,
    // "opaqu"
    -1, -1, -1, -1, -1, 5670, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "opaque"
    ContextualKeyword._opaque << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "ou"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 5724, -1, -1, -1, -1, -1, -1,
    // "out"
    ContextualKeyword._out << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "ov"
    -1, -1, -1, -1, -1, 5778, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "ove"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 5805, -1, -1, -1, -1, -1, -1, -1, -1,
    // "over"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 5832, -1, -1, -1, -1, -1, -1, -1, -1,
    // "overr"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, 5859, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "overri"
    -1, -1, -1, -1, 5886, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "overrid"
    -1, -1, -1, -1, -1, 5913, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "override"
    ContextualKeyword._override << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "p"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 5967, -1, -1, 6345, -1, -1, -1, -1, -1,
    // "pr"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, 5994, -1, -1, -1, -1, -1, 6129, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "pri"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 6021, -1, -1, -1, -1,
    // "priv"
    -1, 6048, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "priva"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 6075, -1, -1, -1, -1, -1, -1,
    // "privat"
    -1, -1, -1, -1, -1, 6102, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "private"
    ContextualKeyword._private << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "pro"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 6156, -1, -1, -1, -1, -1, -1,
    // "prot"
    -1, -1, -1, -1, -1, 6183, -1, -1, -1, -1, -1, -1, -1, -1, -1, 6318, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "prote"
    -1, -1, -1, 6210, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "protec"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 6237, -1, -1, -1, -1, -1, -1,
    // "protect"
    -1, -1, -1, -1, -1, 6264, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "protecte"
    -1, -1, -1, -1, 6291, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "protected"
    ContextualKeyword._protected << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "proto"
    ContextualKeyword._proto << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "pu"
    -1, -1, 6372, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "pub"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 6399, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "publ"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, 6426, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "publi"
    -1, -1, -1, 6453, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "public"
    ContextualKeyword._public << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "r"
    -1, -1, -1, -1, -1, 6507, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "re"
    -1, 6534, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 6696, -1, -1, 6831, -1, -1, -1, -1, -1, -1,
    // "rea"
    -1, -1, -1, -1, 6561, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "read"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 6588, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "reado"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 6615, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "readon"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 6642, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "readonl"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 6669, -1,
    // "readonly"
    ContextualKeyword._readonly << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "req"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 6723, -1, -1, -1, -1, -1,
    // "requ"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, 6750, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "requi"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 6777, -1, -1, -1, -1, -1, -1, -1, -1,
    // "requir"
    -1, -1, -1, -1, -1, 6804, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "require"
    ContextualKeyword._require << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "ret"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 6858, -1, -1, -1, -1, -1,
    // "retu"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 6885, -1, -1, -1, -1, -1, -1, -1, -1,
    // "retur"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 6912, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "return"
    (TokenType._return << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "s"
    -1, 6966, -1, -1, -1, 7182, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 7236, 7371, -1, 7479, -1, 7614, -1,
    // "sa"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 6993, -1, -1, -1, -1, -1, -1,
    // "sat"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, 7020, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "sati"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 7047, -1, -1, -1, -1, -1, -1, -1,
    // "satis"
    -1, -1, -1, -1, -1, -1, 7074, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "satisf"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, 7101, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "satisfi"
    -1, -1, -1, -1, -1, 7128, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "satisfie"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 7155, -1, -1, -1, -1, -1, -1, -1,
    // "satisfies"
    ContextualKeyword._satisfies << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "se"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 7209, -1, -1, -1, -1, -1, -1,
    // "set"
    ContextualKeyword._set << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "st"
    -1, 7263, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "sta"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 7290, -1, -1, -1, -1, -1, -1,
    // "stat"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, 7317, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "stati"
    -1, -1, -1, 7344, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "static"
    ContextualKeyword._static << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "su"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 7398, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "sup"
    -1, -1, -1, -1, -1, 7425, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "supe"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 7452, -1, -1, -1, -1, -1, -1, -1, -1,
    // "super"
    (TokenType._super << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "sw"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, 7506, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "swi"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 7533, -1, -1, -1, -1, -1, -1,
    // "swit"
    -1, -1, -1, 7560, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "switc"
    -1, -1, -1, -1, -1, -1, -1, -1, 7587, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "switch"
    (TokenType._switch << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "sy"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 7641, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "sym"
    -1, -1, 7668, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "symb"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 7695, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "symbo"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 7722, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "symbol"
    ContextualKeyword._symbol << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "t"
    -1, -1, -1, -1, -1, -1, -1, -1, 7776, -1, -1, -1, -1, -1, -1, -1, -1, -1, 7938, -1, -1, -1, -1, -1, -1, 8046, -1,
    // "th"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, 7803, -1, -1, -1, -1, -1, -1, -1, -1, 7857, -1, -1, -1, -1, -1, -1, -1, -1,
    // "thi"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 7830, -1, -1, -1, -1, -1, -1, -1,
    // "this"
    (TokenType._this << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "thr"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 7884, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "thro"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 7911, -1, -1, -1,
    // "throw"
    (TokenType._throw << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "tr"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 7965, -1, -1, -1, 8019, -1,
    // "tru"
    -1, -1, -1, -1, -1, 7992, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "true"
    (TokenType._true << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "try"
    (TokenType._try << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "ty"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 8073, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "typ"
    -1, -1, -1, -1, -1, 8100, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "type"
    ContextualKeyword._type << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 8127, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "typeo"
    -1, -1, -1, -1, -1, -1, 8154, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "typeof"
    (TokenType._typeof << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "u"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 8208, -1, -1, -1, -1, 8343, -1, -1, -1, -1, -1, -1, -1,
    // "un"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, 8235, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "uni"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 8262, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "uniq"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 8289, -1, -1, -1, -1, -1,
    // "uniqu"
    -1, -1, -1, -1, -1, 8316, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "unique"
    ContextualKeyword._unique << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "us"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, 8370, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "usi"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 8397, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "usin"
    -1, -1, -1, -1, -1, -1, -1, 8424, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "using"
    ContextualKeyword._using << 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "v"
    -1, 8478, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 8532, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "va"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 8505, -1, -1, -1, -1, -1, -1, -1, -1,
    // "var"
    (TokenType._var << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "vo"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, 8559, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "voi"
    -1, -1, -1, -1, 8586, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "void"
    (TokenType._void << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "w"
    -1, -1, -1, -1, -1, -1, -1, -1, 8640, 8748, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "wh"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, 8667, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "whi"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 8694, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "whil"
    -1, -1, -1, -1, -1, 8721, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "while"
    (TokenType._while << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "wi"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 8775, -1, -1, -1, -1, -1, -1,
    // "wit"
    -1, -1, -1, -1, -1, -1, -1, -1, 8802, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "with"
    (TokenType._with << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "y"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, 8856, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "yi"
    -1, -1, -1, -1, -1, 8883, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "yie"
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 8910, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "yiel"
    -1, -1, -1, -1, 8937, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    // "yield"
    (TokenType._yield << 1) + 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
]);

/**
 * Read an identifier, producing either a name token or matching on one of the existing keywords.
 * For performance, we pre-generate big decision tree that we traverse. Each node represents a
 * prefix and has 27 values, where the first value is the token or contextual token, if any (-1 if
 * not), and the other 26 values are the transitions to other nodes, or -1 to stop.
 */
function readWord() {
    let treePos = 0;
    let code = 0;
    let pos = state.pos;
    while (pos < input.length) {
        code = input.charCodeAt(pos);
        if (code < charCodes.lowercaseA || code > charCodes.lowercaseZ) {
            break;
        }
        const next = READ_WORD_TREE[treePos + (code - charCodes.lowercaseA) + 1];
        if (next === -1) {
            break;
        }
        else {
            treePos = next;
            pos++;
        }
    }
    const keywordValue = READ_WORD_TREE[treePos];
    if (keywordValue > -1 && !IS_IDENTIFIER_CHAR[code]) {
        state.pos = pos;
        if (keywordValue & 1) {
            finishToken(keywordValue >>> 1);
        }
        else {
            finishToken(TokenType.name, keywordValue >>> 1);
        }
        return;
    }
    while (pos < input.length) {
        const ch = input.charCodeAt(pos);
        if (IS_IDENTIFIER_CHAR[ch]) {
            pos++;
        }
        else if (ch === charCodes.backslash) {
            // \u
            pos += 2;
            if (input.charCodeAt(pos) === charCodes.leftCurlyBrace) {
                while (pos < input.length && input.charCodeAt(pos) !== charCodes.rightCurlyBrace) {
                    pos++;
                }
                pos++;
            }
        }
        else if (ch === charCodes.atSign && input.charCodeAt(pos + 1) === charCodes.atSign) {
            pos += 2;
        }
        else {
            break;
        }
    }
    state.pos = pos;
    finishToken(TokenType.name);
}

/* eslint max-len: 0 */
var IdentifierRole;
(function (IdentifierRole) {
    IdentifierRole[IdentifierRole["Access"] = 0] = "Access";
    IdentifierRole[IdentifierRole["ExportAccess"] = 1] = "ExportAccess";
    IdentifierRole[IdentifierRole["TopLevelDeclaration"] = 2] = "TopLevelDeclaration";
    IdentifierRole[IdentifierRole["FunctionScopedDeclaration"] = 3] = "FunctionScopedDeclaration";
    IdentifierRole[IdentifierRole["BlockScopedDeclaration"] = 4] = "BlockScopedDeclaration";
    IdentifierRole[IdentifierRole["ObjectShorthandTopLevelDeclaration"] = 5] = "ObjectShorthandTopLevelDeclaration";
    IdentifierRole[IdentifierRole["ObjectShorthandFunctionScopedDeclaration"] = 6] = "ObjectShorthandFunctionScopedDeclaration";
    IdentifierRole[IdentifierRole["ObjectShorthandBlockScopedDeclaration"] = 7] = "ObjectShorthandBlockScopedDeclaration";
    IdentifierRole[IdentifierRole["ObjectShorthand"] = 8] = "ObjectShorthand";
    // Any identifier bound in an import statement, e.g. both A and b from
    // `import A, * as b from 'A';`
    IdentifierRole[IdentifierRole["ImportDeclaration"] = 9] = "ImportDeclaration";
    IdentifierRole[IdentifierRole["ObjectKey"] = 10] = "ObjectKey";
    // The `foo` in `import {foo as bar} from "./abc";`.
    IdentifierRole[IdentifierRole["ImportAccess"] = 11] = "ImportAccess";
})(IdentifierRole || (IdentifierRole = {}));
/**
 * Extra information on jsxTagStart tokens, used to determine which of the three
 * jsx functions are called in the automatic transform.
 */
var JSXRole;
(function (JSXRole) {
    // The element is self-closing or has a body that resolves to empty. We
    // shouldn't emit children at all in this case.
    JSXRole[JSXRole["NoChildren"] = 0] = "NoChildren";
    // The element has a single explicit child, which might still be an arbitrary
    // expression like an array. We should emit that expression as the children.
    JSXRole[JSXRole["OneChild"] = 1] = "OneChild";
    // The element has at least two explicitly-specified children or has spread
    // children, so child positions are assumed to be "static". We should wrap
    // these children in an array.
    JSXRole[JSXRole["StaticChildren"] = 2] = "StaticChildren";
    // The element has a prop named "key" after a prop spread, so we should fall
    // back to the createElement function.
    JSXRole[JSXRole["KeyAfterPropSpread"] = 3] = "KeyAfterPropSpread";
})(JSXRole || (JSXRole = {}));
// Object type used to represent tokens. Note that normally, tokens
// simply exist as properties on the parser object. This is only
// used for the onToken callback and the external tokenizer.
class Token {
    constructor() {
        this.type = state.type;
        this.contextualKeyword = state.contextualKeyword;
        this.start = state.start;
        this.end = state.end;
        this.scopeDepth = state.scopeDepth;
        this.isType = state.isType;
        this.identifierRole = null;
        this.jsxRole = null;
        this.shadowsGlobal = false;
        this.isAsyncOperation = false;
        this.contextId = null;
        this.rhsEndIndex = null;
        this.isExpression = false;
        this.numNullishCoalesceStarts = 0;
        this.numNullishCoalesceEnds = 0;
        this.isOptionalChainStart = false;
        this.isOptionalChainEnd = false;
        this.subscriptStartIndex = null;
        this.nullishStartIndex = null;
    }
    type;
    contextualKeyword;
    start;
    end;
    scopeDepth;
    isType;
    identifierRole;
    jsxRole;
    // Initially false for all tokens, then may be computed in a follow-up step that does scope
    // analysis.
    shadowsGlobal;
    // Initially false for all tokens, but may be set during transform to mark it as containing an
    // await operation.
    isAsyncOperation;
    contextId;
    // For assignments, the index of the RHS. For export tokens, the end of the export.
    rhsEndIndex;
    // For class tokens, records if the class is a class expression or a class statement.
    isExpression;
    // Number of times to insert a `nullishCoalesce(` snippet before this token.
    numNullishCoalesceStarts;
    // Number of times to insert a `)` snippet after this token.
    numNullishCoalesceEnds;
    // If true, insert an `optionalChain([` snippet before this token.
    isOptionalChainStart;
    // If true, insert a `])` snippet after this token.
    isOptionalChainEnd;
    // Tag for `.`, `?.`, `[`, `?.[`, `(`, and `?.(` to denote the "root" token for this
    // subscript chain. This can be used to determine if this chain is an optional chain.
    subscriptStartIndex;
    // Tag for `??` operators to denote the root token for this nullish coalescing call.
    nullishStartIndex;
}
// ## Tokenizer
// Move to the next token
function next() {
    state.tokens.push(new Token());
    nextToken();
}
// Call instead of next when inside a template, since that needs to be handled differently.
function nextTemplateToken() {
    state.tokens.push(new Token());
    state.start = state.pos;
    readTmplToken();
}
// The tokenizer never parses regexes by default. Instead, the parser is responsible for
// instructing it to parse a regex when we see a slash at the start of an expression.
function retokenizeSlashAsRegex() {
    if (state.type === TokenType.assign) {
        --state.pos;
    }
    readRegexp();
}
function pushTypeContext(existingTokensInType) {
    for (let i = state.tokens.length - existingTokensInType; i < state.tokens.length; i++) {
        state.tokens[i].isType = true;
    }
    const oldIsType = state.isType;
    state.isType = true;
    return oldIsType;
}
function popTypeContext(oldIsType) {
    state.isType = oldIsType;
}
function eat(type) {
    if (match(type)) {
        next();
        return true;
    }
    else {
        return false;
    }
}
function eatTypeToken(tokenType) {
    const oldIsType = state.isType;
    state.isType = true;
    eat(tokenType);
    state.isType = oldIsType;
}
function match(type) {
    return state.type === type;
}
function lookaheadType() {
    const snapshot = state.snapshot();
    next();
    const type = state.type;
    state.restoreFromSnapshot(snapshot);
    return type;
}
class TypeAndKeyword {
    type;
    contextualKeyword;
    constructor(type, contextualKeyword) {
        this.type = type;
        this.contextualKeyword = contextualKeyword;
    }
}
function lookaheadTypeAndKeyword() {
    const snapshot = state.snapshot();
    next();
    const type = state.type;
    const contextualKeyword = state.contextualKeyword;
    state.restoreFromSnapshot(snapshot);
    return new TypeAndKeyword(type, contextualKeyword);
}
function nextTokenStart() {
    return nextTokenStartSince(state.pos);
}
function nextTokenStartSince(pos) {
    skipWhiteSpace.lastIndex = pos;
    const skip = skipWhiteSpace.exec(input);
    return pos + skip[0].length;
}
function lookaheadCharCode() {
    return input.charCodeAt(nextTokenStart());
}
// Read a single token, updating the parser object's token-related
// properties.
function nextToken() {
    skipSpace();
    state.start = state.pos;
    if (state.pos >= input.length) {
        const tokens = state.tokens;
        // We normally run past the end a bit, but if we're way past the end, avoid an infinite loop.
        // Also check the token positions rather than the types since sometimes we rewrite the token
        // type to something else.
        if (tokens.length >= 2 &&
            tokens[tokens.length - 1].start >= input.length &&
            tokens[tokens.length - 2].start >= input.length) {
            unexpected("Unexpectedly reached the end of input.");
        }
        finishToken(TokenType.eof);
        return;
    }
    readToken(input.charCodeAt(state.pos));
}
function readToken(code) {
    // Identifier or keyword. '\uXXXX' sequences are allowed in
    // identifiers, so '\' also dispatches to that.
    if (IS_IDENTIFIER_START[code] ||
        code === charCodes.backslash ||
        (code === charCodes.atSign && input.charCodeAt(state.pos + 1) === charCodes.atSign)) {
        readWord();
    }
    else {
        getTokenFromCode(code);
    }
}
function skipBlockComment() {
    while (input.charCodeAt(state.pos) !== charCodes.asterisk ||
        input.charCodeAt(state.pos + 1) !== charCodes.slash) {
        state.pos++;
        if (state.pos > input.length) {
            unexpected("Unterminated comment", state.pos - 2);
            return;
        }
    }
    state.pos += 2;
}
function skipLineComment(startSkip) {
    let ch = input.charCodeAt((state.pos += startSkip));
    if (state.pos < input.length) {
        while (ch !== charCodes.lineFeed &&
            ch !== charCodes.carriageReturn &&
            ch !== charCodes.lineSeparator &&
            ch !== charCodes.paragraphSeparator &&
            ++state.pos < input.length) {
            ch = input.charCodeAt(state.pos);
        }
    }
}
// Called at the start of the parse and after every token. Skips
// whitespace and comments.
function skipSpace() {
    while (state.pos < input.length) {
        const ch = input.charCodeAt(state.pos);
        switch (ch) {
            case charCodes.carriageReturn:
                if (input.charCodeAt(state.pos + 1) === charCodes.lineFeed) {
                    ++state.pos;
                }
            case charCodes.lineFeed:
            case charCodes.lineSeparator:
            case charCodes.paragraphSeparator:
                ++state.pos;
                break;
            case charCodes.slash:
                switch (input.charCodeAt(state.pos + 1)) {
                    case charCodes.asterisk:
                        state.pos += 2;
                        skipBlockComment();
                        break;
                    case charCodes.slash:
                        skipLineComment(2);
                        break;
                    default:
                        return;
                }
                break;
            default:
                if (IS_WHITESPACE[ch]) {
                    ++state.pos;
                }
                else {
                    return;
                }
        }
    }
}
// Called at the end of every token. Sets various fields, and skips the space after the token, so
// that the next one's `start` will point at the right position.
function finishToken(type, contextualKeyword = ContextualKeyword.NONE) {
    state.end = state.pos;
    state.type = type;
    state.contextualKeyword = contextualKeyword;
}
// ### Token reading
// This is the function that is called to fetch the next token. It
// is somewhat obscure, because it works in character codes rather
// than characters, and because operator parsing has been inlined
// into it.
//
// All in the name of speed.
function readToken_dot() {
    const nextChar = input.charCodeAt(state.pos + 1);
    if (nextChar >= charCodes.digit0 && nextChar <= charCodes.digit9) {
        readNumber(true);
        return;
    }
    if (nextChar === charCodes.dot && input.charCodeAt(state.pos + 2) === charCodes.dot) {
        state.pos += 3;
        finishToken(TokenType.ellipsis);
    }
    else {
        ++state.pos;
        finishToken(TokenType.dot);
    }
}
function readToken_slash() {
    const nextChar = input.charCodeAt(state.pos + 1);
    if (nextChar === charCodes.equalsTo) {
        finishOp(TokenType.assign, 2);
    }
    else {
        finishOp(TokenType.slash, 1);
    }
}
function readToken_mult_modulo(code) {
    // '%*'
    let tokenType = code === charCodes.asterisk ? TokenType.star : TokenType.modulo;
    let width = 1;
    let nextChar = input.charCodeAt(state.pos + 1);
    // Exponentiation operator **
    if (code === charCodes.asterisk && nextChar === charCodes.asterisk) {
        width++;
        nextChar = input.charCodeAt(state.pos + 2);
        tokenType = TokenType.exponent;
    }
    // Match *= or %=, disallowing *=> which can be valid in flow.
    if (nextChar === charCodes.equalsTo &&
        input.charCodeAt(state.pos + 2) !== charCodes.greaterThan) {
        width++;
        tokenType = TokenType.assign;
    }
    finishOp(tokenType, width);
}
function readToken_pipe_amp(code) {
    // '|&'
    const nextChar = input.charCodeAt(state.pos + 1);
    if (nextChar === code) {
        if (input.charCodeAt(state.pos + 2) === charCodes.equalsTo) {
            // ||= or &&=
            finishOp(TokenType.assign, 3);
        }
        else {
            // || or &&
            finishOp(code === charCodes.verticalBar ? TokenType.logicalOR : TokenType.logicalAND, 2);
        }
        return;
    }
    if (code === charCodes.verticalBar) {
        // '|>'
        if (nextChar === charCodes.greaterThan) {
            finishOp(TokenType.pipeline, 2);
            return;
        }
        else if (nextChar === charCodes.rightCurlyBrace && isFlowEnabled) {
            // '|}'
            finishOp(TokenType.braceBarR, 2);
            return;
        }
    }
    if (nextChar === charCodes.equalsTo) {
        finishOp(TokenType.assign, 2);
        return;
    }
    finishOp(code === charCodes.verticalBar ? TokenType.bitwiseOR : TokenType.bitwiseAND, 1);
}
function readToken_caret() {
    // '^'
    const nextChar = input.charCodeAt(state.pos + 1);
    if (nextChar === charCodes.equalsTo) {
        finishOp(TokenType.assign, 2);
    }
    else {
        finishOp(TokenType.bitwiseXOR, 1);
    }
}
function readToken_plus_min(code) {
    // '+-'
    const nextChar = input.charCodeAt(state.pos + 1);
    if (nextChar === code) {
        // Tentatively call this a prefix operator, but it might be changed to postfix later.
        finishOp(TokenType.preIncDec, 2);
        return;
    }
    if (nextChar === charCodes.equalsTo) {
        finishOp(TokenType.assign, 2);
    }
    else if (code === charCodes.plusSign) {
        finishOp(TokenType.plus, 1);
    }
    else {
        finishOp(TokenType.minus, 1);
    }
}
function readToken_lt() {
    const nextChar = input.charCodeAt(state.pos + 1);
    if (nextChar === charCodes.lessThan) {
        if (input.charCodeAt(state.pos + 2) === charCodes.equalsTo) {
            finishOp(TokenType.assign, 3);
            return;
        }
        // We see <<, but need to be really careful about whether to treat it as a
        // true left-shift or as two < tokens.
        if (state.isType) {
            // Within a type, << might come up in a snippet like `Array<<T>() => void>`,
            // so treat it as two < tokens. Importantly, this should only override <<
            // rather than other tokens like <= . If we treated <= as < in a type
            // context, then the snippet `a as T <= 1` would incorrectly start parsing
            // a type argument on T. We don't need to worry about `a as T << 1`
            // because TypeScript disallows that syntax.
            finishOp(TokenType.lessThan, 1);
        }
        else {
            // Outside a type, this might be a true left-shift operator, or it might
            // still be two open-type-arg tokens, such as in `f<<T>() => void>()`. We
            // look at the token while considering the `f`, so we don't yet know that
            // we're in a type context. In this case, we initially tokenize as a
            // left-shift and correct after-the-fact as necessary in
            // tsParseTypeArgumentsWithPossibleBitshift .
            finishOp(TokenType.bitShiftL, 2);
        }
        return;
    }
    if (nextChar === charCodes.equalsTo) {
        // <=
        finishOp(TokenType.relationalOrEqual, 2);
    }
    else {
        finishOp(TokenType.lessThan, 1);
    }
}
function readToken_gt() {
    if (state.isType) {
        // Avoid right-shift for things like `Array<Array<string>>` and
        // greater-than-or-equal for things like `const a: Array<number>=[];`.
        finishOp(TokenType.greaterThan, 1);
        return;
    }
    const nextChar = input.charCodeAt(state.pos + 1);
    if (nextChar === charCodes.greaterThan) {
        const size = input.charCodeAt(state.pos + 2) === charCodes.greaterThan ? 3 : 2;
        if (input.charCodeAt(state.pos + size) === charCodes.equalsTo) {
            finishOp(TokenType.assign, size + 1);
            return;
        }
        finishOp(TokenType.bitShiftR, size);
        return;
    }
    if (nextChar === charCodes.equalsTo) {
        // >=
        finishOp(TokenType.relationalOrEqual, 2);
    }
    else {
        finishOp(TokenType.greaterThan, 1);
    }
}
/**
 * Reinterpret a possible > token when transitioning from a type to a non-type
 * context.
 *
 * This comes up in two situations where >= needs to be treated as one token:
 * - After an `as` expression, like in the code `a as T >= 1`.
 * - In a type argument in an expression context, e.g. `f(a < b, c >= d)`, we
 *   need to see the token as >= so that we get an error and backtrack to
 *   normal expression parsing.
 *
 * Other situations require >= to be seen as two tokens, e.g.
 * `const x: Array<T>=[];`, so it's important to treat > as its own token in
 * typical type parsing situations.
 */
function rescan_gt() {
    if (state.type === TokenType.greaterThan) {
        state.pos -= 1;
        readToken_gt();
    }
}
function readToken_eq_excl(code) {
    // '=!'
    const nextChar = input.charCodeAt(state.pos + 1);
    if (nextChar === charCodes.equalsTo) {
        finishOp(TokenType.equality, input.charCodeAt(state.pos + 2) === charCodes.equalsTo ? 3 : 2);
        return;
    }
    if (code === charCodes.equalsTo && nextChar === charCodes.greaterThan) {
        // '=>'
        state.pos += 2;
        finishToken(TokenType.arrow);
        return;
    }
    finishOp(code === charCodes.equalsTo ? TokenType.eq : TokenType.bang, 1);
}
function readToken_question() {
    // '?'
    const nextChar = input.charCodeAt(state.pos + 1);
    const nextChar2 = input.charCodeAt(state.pos + 2);
    if (nextChar === charCodes.questionMark &&
        // In Flow (but not TypeScript), ??string is a valid type that should be
        // tokenized as two individual ? tokens.
        !(isFlowEnabled && state.isType)) {
        if (nextChar2 === charCodes.equalsTo) {
            // '??='
            finishOp(TokenType.assign, 3);
        }
        else {
            // '??'
            finishOp(TokenType.nullishCoalescing, 2);
        }
    }
    else if (nextChar === charCodes.dot &&
        !(nextChar2 >= charCodes.digit0 && nextChar2 <= charCodes.digit9)) {
        // '.' not followed by a number
        state.pos += 2;
        finishToken(TokenType.questionDot);
    }
    else {
        ++state.pos;
        finishToken(TokenType.question);
    }
}
function getTokenFromCode(code) {
    switch (code) {
        case charCodes.numberSign:
            ++state.pos;
            finishToken(TokenType.hash);
            return;
        // The interpretation of a dot depends on whether it is followed
        // by a digit or another two dots.
        case charCodes.dot:
            readToken_dot();
            return;
        // Punctuation tokens.
        case charCodes.leftParenthesis:
            ++state.pos;
            finishToken(TokenType.parenL);
            return;
        case charCodes.rightParenthesis:
            ++state.pos;
            finishToken(TokenType.parenR);
            return;
        case charCodes.semicolon:
            ++state.pos;
            finishToken(TokenType.semi);
            return;
        case charCodes.comma:
            ++state.pos;
            finishToken(TokenType.comma);
            return;
        case charCodes.leftSquareBracket:
            ++state.pos;
            finishToken(TokenType.bracketL);
            return;
        case charCodes.rightSquareBracket:
            ++state.pos;
            finishToken(TokenType.bracketR);
            return;
        case charCodes.leftCurlyBrace:
            if (isFlowEnabled && input.charCodeAt(state.pos + 1) === charCodes.verticalBar) {
                finishOp(TokenType.braceBarL, 2);
            }
            else {
                ++state.pos;
                finishToken(TokenType.braceL);
            }
            return;
        case charCodes.rightCurlyBrace:
            ++state.pos;
            finishToken(TokenType.braceR);
            return;
        case charCodes.colon:
            if (input.charCodeAt(state.pos + 1) === charCodes.colon) {
                finishOp(TokenType.doubleColon, 2);
            }
            else {
                ++state.pos;
                finishToken(TokenType.colon);
            }
            return;
        case charCodes.questionMark:
            readToken_question();
            return;
        case charCodes.atSign:
            ++state.pos;
            finishToken(TokenType.at);
            return;
        case charCodes.graveAccent:
            ++state.pos;
            finishToken(TokenType.backQuote);
            return;
        case charCodes.digit0: {
            const nextChar = input.charCodeAt(state.pos + 1);
            // '0x', '0X', '0o', '0O', '0b', '0B'
            if (nextChar === charCodes.lowercaseX ||
                nextChar === charCodes.uppercaseX ||
                nextChar === charCodes.lowercaseO ||
                nextChar === charCodes.uppercaseO ||
                nextChar === charCodes.lowercaseB ||
                nextChar === charCodes.uppercaseB) {
                readRadixNumber();
                return;
            }
        }
        // Anything else beginning with a digit is an integer, octal
        // number, or float.
        case charCodes.digit1:
        case charCodes.digit2:
        case charCodes.digit3:
        case charCodes.digit4:
        case charCodes.digit5:
        case charCodes.digit6:
        case charCodes.digit7:
        case charCodes.digit8:
        case charCodes.digit9:
            readNumber(false);
            return;
        // Quotes produce strings.
        case charCodes.quotationMark:
        case charCodes.apostrophe:
            readString(code);
            return;
        // Operators are parsed inline in tiny state machines. '=' (charCodes.equalsTo) is
        // often referred to. `finishOp` simply skips the amount of
        // characters it is given as second argument, and returns a token
        // of the type given by its first argument.
        case charCodes.slash:
            readToken_slash();
            return;
        case charCodes.percentSign:
        case charCodes.asterisk:
            readToken_mult_modulo(code);
            return;
        case charCodes.verticalBar:
        case charCodes.ampersand:
            readToken_pipe_amp(code);
            return;
        case charCodes.caret:
            readToken_caret();
            return;
        case charCodes.plusSign:
        case charCodes.dash:
            readToken_plus_min(code);
            return;
        case charCodes.lessThan:
            readToken_lt();
            return;
        case charCodes.greaterThan:
            readToken_gt();
            return;
        case charCodes.equalsTo:
        case charCodes.exclamationMark:
            readToken_eq_excl(code);
            return;
        case charCodes.tilde:
            finishOp(TokenType.tilde, 1);
            return;
    }
    unexpected(`Unexpected character '${String.fromCharCode(code)}'`, state.pos);
}
function finishOp(type, size) {
    state.pos += size;
    finishToken(type);
}
function readRegexp() {
    const start = state.pos;
    let escaped = false;
    let inClass = false;
    for (;;) {
        if (state.pos >= input.length) {
            unexpected("Unterminated regular expression", start);
            return;
        }
        const code = input.charCodeAt(state.pos);
        if (escaped) {
            escaped = false;
        }
        else {
            if (code === charCodes.leftSquareBracket) {
                inClass = true;
            }
            else if (code === charCodes.rightSquareBracket && inClass) {
                inClass = false;
            }
            else if (code === charCodes.slash && !inClass) {
                break;
            }
            escaped = code === charCodes.backslash;
        }
        ++state.pos;
    }
    ++state.pos;
    // Need to use `skipWord` because '\uXXXX' sequences are allowed here (don't ask).
    skipWord();
    finishToken(TokenType.regexp);
}
/**
 * Read a decimal integer. Note that this can't be unified with the similar code
 * in readRadixNumber (which also handles hex digits) because "e" needs to be
 * the end of the integer so that we can properly handle scientific notation.
 */
function readInt() {
    while (true) {
        const code = input.charCodeAt(state.pos);
        if ((code >= charCodes.digit0 && code <= charCodes.digit9) || code === charCodes.underscore) {
            state.pos++;
        }
        else {
            break;
        }
    }
}
function readRadixNumber() {
    state.pos += 2; // 0x
    // Walk to the end of the number, allowing hex digits.
    while (true) {
        const code = input.charCodeAt(state.pos);
        if ((code >= charCodes.digit0 && code <= charCodes.digit9) ||
            (code >= charCodes.lowercaseA && code <= charCodes.lowercaseF) ||
            (code >= charCodes.uppercaseA && code <= charCodes.uppercaseF) ||
            code === charCodes.underscore) {
            state.pos++;
        }
        else {
            break;
        }
    }
    const nextChar = input.charCodeAt(state.pos);
    if (nextChar === charCodes.lowercaseN) {
        ++state.pos;
        finishToken(TokenType.bigint);
    }
    else {
        finishToken(TokenType.num);
    }
}
// Read an integer, octal integer, or floating-point number.
function readNumber(startsWithDot) {
    let isBigInt = false;
    let isDecimal = false;
    if (!startsWithDot) {
        readInt();
    }
    let nextChar = input.charCodeAt(state.pos);
    if (nextChar === charCodes.dot) {
        ++state.pos;
        readInt();
        nextChar = input.charCodeAt(state.pos);
    }
    if (nextChar === charCodes.uppercaseE || nextChar === charCodes.lowercaseE) {
        nextChar = input.charCodeAt(++state.pos);
        if (nextChar === charCodes.plusSign || nextChar === charCodes.dash) {
            ++state.pos;
        }
        readInt();
        nextChar = input.charCodeAt(state.pos);
    }
    if (nextChar === charCodes.lowercaseN) {
        ++state.pos;
        isBigInt = true;
    }
    else if (nextChar === charCodes.lowercaseM) {
        ++state.pos;
        isDecimal = true;
    }
    if (isBigInt) {
        finishToken(TokenType.bigint);
        return;
    }
    if (isDecimal) {
        finishToken(TokenType.decimal);
        return;
    }
    finishToken(TokenType.num);
}
function readString(quote) {
    state.pos++;
    for (;;) {
        if (state.pos >= input.length) {
            unexpected("Unterminated string constant");
            return;
        }
        const ch = input.charCodeAt(state.pos);
        if (ch === charCodes.backslash) {
            state.pos++;
        }
        else if (ch === quote) {
            break;
        }
        state.pos++;
    }
    state.pos++;
    finishToken(TokenType.string);
}
// Reads template string tokens.
function readTmplToken() {
    for (;;) {
        if (state.pos >= input.length) {
            unexpected("Unterminated template");
            return;
        }
        const ch = input.charCodeAt(state.pos);
        if (ch === charCodes.graveAccent ||
            (ch === charCodes.dollarSign && input.charCodeAt(state.pos + 1) === charCodes.leftCurlyBrace)) {
            if (state.pos === state.start && match(TokenType.template)) {
                if (ch === charCodes.dollarSign) {
                    state.pos += 2;
                    finishToken(TokenType.dollarBraceL);
                    return;
                }
                else {
                    ++state.pos;
                    finishToken(TokenType.backQuote);
                    return;
                }
            }
            finishToken(TokenType.template);
            return;
        }
        if (ch === charCodes.backslash) {
            state.pos++;
        }
        state.pos++;
    }
}
// Skip to the end of the current word. Note that this is the same as the snippet at the end of
// readWord, but calling skipWord from readWord seems to slightly hurt performance from some rough
// measurements.
function skipWord() {
    while (state.pos < input.length) {
        const ch = input.charCodeAt(state.pos);
        if (IS_IDENTIFIER_CHAR[ch]) {
            state.pos++;
        }
        else if (ch === charCodes.backslash) {
            // \u
            state.pos += 2;
            if (input.charCodeAt(state.pos) === charCodes.leftCurlyBrace) {
                while (state.pos < input.length &&
                    input.charCodeAt(state.pos) !== charCodes.rightCurlyBrace) {
                    state.pos++;
                }
                state.pos++;
            }
        }
        else {
            break;
        }
    }
}

function parseSpread() {
    next();
    parseMaybeAssign(false);
}
function parseRest(isBlockScope) {
    next();
    parseBindingAtom(isBlockScope);
}
function parseBindingIdentifier(isBlockScope) {
    parseIdentifier();
    markPriorBindingIdentifier(isBlockScope);
}
function parseImportedIdentifier() {
    parseIdentifier();
    state.tokens[state.tokens.length - 1].identifierRole = IdentifierRole.ImportDeclaration;
}
function markPriorBindingIdentifier(isBlockScope) {
    let identifierRole;
    if (state.scopeDepth === 0) {
        identifierRole = IdentifierRole.TopLevelDeclaration;
    }
    else if (isBlockScope) {
        identifierRole = IdentifierRole.BlockScopedDeclaration;
    }
    else {
        identifierRole = IdentifierRole.FunctionScopedDeclaration;
    }
    state.tokens[state.tokens.length - 1].identifierRole = identifierRole;
}
// Parses lvalue (assignable) atom.
function parseBindingAtom(isBlockScope) {
    switch (state.type) {
        case TokenType._this: {
            // In TypeScript, "this" may be the name of a parameter, so allow it.
            const oldIsType = pushTypeContext(0);
            next();
            popTypeContext(oldIsType);
            return;
        }
        case TokenType._yield:
        case TokenType.name: {
            state.type = TokenType.name;
            parseBindingIdentifier(isBlockScope);
            return;
        }
        case TokenType.bracketL: {
            next();
            parseBindingList(TokenType.bracketR, isBlockScope, true /* allowEmpty */);
            return;
        }
        case TokenType.braceL:
            parseObj(true, isBlockScope);
            return;
        default:
            unexpected();
    }
}
function parseBindingList(close, isBlockScope, allowEmpty = false, allowModifiers = false, contextId = 0) {
    let first = true;
    let hasRemovedComma = false;
    const firstItemTokenIndex = state.tokens.length;
    while (!eat(close) && !state.error) {
        if (first) {
            first = false;
        }
        else {
            expect(TokenType.comma);
            state.tokens[state.tokens.length - 1].contextId = contextId;
            // After a "this" type in TypeScript, we need to set the following comma (if any) to also be
            // a type token so that it will be removed.
            if (!hasRemovedComma && state.tokens[firstItemTokenIndex].isType) {
                state.tokens[state.tokens.length - 1].isType = true;
                hasRemovedComma = true;
            }
        }
        if (allowEmpty && match(TokenType.comma)) ;
        else if (eat(close)) {
            break;
        }
        else if (match(TokenType.ellipsis)) {
            parseRest(isBlockScope);
            parseAssignableListItemTypes();
            // Support rest element trailing commas allowed by TypeScript <2.9.
            eat(TokenType.comma);
            expect(close);
            break;
        }
        else {
            parseAssignableListItem(allowModifiers, isBlockScope);
        }
    }
}
function parseAssignableListItem(allowModifiers, isBlockScope) {
    if (allowModifiers) {
        tsParseModifiers([
            ContextualKeyword._public,
            ContextualKeyword._protected,
            ContextualKeyword._private,
            ContextualKeyword._readonly,
            ContextualKeyword._override,
        ]);
    }
    parseMaybeDefault(isBlockScope);
    parseAssignableListItemTypes();
    parseMaybeDefault(isBlockScope, true /* leftAlreadyParsed */);
}
function parseAssignableListItemTypes() {
    if (isFlowEnabled) {
        flowParseAssignableListItemTypes();
    }
    else if (isTypeScriptEnabled) {
        tsParseAssignableListItemTypes();
    }
}
// Parses assignment pattern around given atom if possible.
function parseMaybeDefault(isBlockScope, leftAlreadyParsed = false) {
    if (!leftAlreadyParsed) {
        parseBindingAtom(isBlockScope);
    }
    if (!eat(TokenType.eq)) {
        return;
    }
    const eqIndex = state.tokens.length - 1;
    parseMaybeAssign();
    state.tokens[eqIndex].rhsEndIndex = state.tokens.length;
}

function tsIsIdentifier() {
    // TODO: actually a bit more complex in TypeScript, but shouldn't matter.
    // See https://github.com/Microsoft/TypeScript/issues/15008
    return match(TokenType.name);
}
function isLiteralPropertyName() {
    return (match(TokenType.name) ||
        Boolean(state.type & TokenType.IS_KEYWORD) ||
        match(TokenType.string) ||
        match(TokenType.num) ||
        match(TokenType.bigint) ||
        match(TokenType.decimal));
}
function tsNextTokenCanFollowModifier() {
    // Note: TypeScript's implementation is much more complicated because
    // more things are considered modifiers there.
    // This implementation only handles modifiers not handled by babylon itself. And "static".
    // TODO: Would be nice to avoid lookahead. Want a hasLineBreakUpNext() method...
    const snapshot = state.snapshot();
    next();
    const canFollowModifier = (match(TokenType.bracketL) ||
        match(TokenType.braceL) ||
        match(TokenType.star) ||
        match(TokenType.ellipsis) ||
        match(TokenType.hash) ||
        isLiteralPropertyName()) &&
        !hasPrecedingLineBreak();
    if (canFollowModifier) {
        return true;
    }
    else {
        state.restoreFromSnapshot(snapshot);
        return false;
    }
}
function tsParseModifiers(allowedModifiers) {
    while (true) {
        const modifier = tsParseModifier(allowedModifiers);
        if (modifier === null) {
            break;
        }
    }
}
/** Parses a modifier matching one the given modifier names. */
function tsParseModifier(allowedModifiers) {
    if (!match(TokenType.name)) {
        return null;
    }
    const modifier = state.contextualKeyword;
    if (allowedModifiers.indexOf(modifier) !== -1 && tsNextTokenCanFollowModifier()) {
        switch (modifier) {
            case ContextualKeyword._readonly:
                state.tokens[state.tokens.length - 1].type = TokenType._readonly;
                break;
            case ContextualKeyword._abstract:
                state.tokens[state.tokens.length - 1].type = TokenType._abstract;
                break;
            case ContextualKeyword._static:
                state.tokens[state.tokens.length - 1].type = TokenType._static;
                break;
            case ContextualKeyword._public:
                state.tokens[state.tokens.length - 1].type = TokenType._public;
                break;
            case ContextualKeyword._private:
                state.tokens[state.tokens.length - 1].type = TokenType._private;
                break;
            case ContextualKeyword._protected:
                state.tokens[state.tokens.length - 1].type = TokenType._protected;
                break;
            case ContextualKeyword._override:
                state.tokens[state.tokens.length - 1].type = TokenType._override;
                break;
            case ContextualKeyword._declare:
                state.tokens[state.tokens.length - 1].type = TokenType._declare;
                break;
        }
        return modifier;
    }
    return null;
}
function tsParseEntityName() {
    parseIdentifier();
    while (eat(TokenType.dot)) {
        parseIdentifier();
    }
}
function tsParseTypeReference() {
    tsParseEntityName();
    if (!hasPrecedingLineBreak() && match(TokenType.lessThan)) {
        tsParseTypeArguments();
    }
}
function tsParseThisTypePredicate() {
    next();
    tsParseTypeAnnotation();
}
function tsParseThisTypeNode() {
    next();
}
function tsParseTypeQuery() {
    expect(TokenType._typeof);
    if (match(TokenType._import)) {
        tsParseImportType();
    }
    else {
        tsParseEntityName();
    }
    if (!hasPrecedingLineBreak() && match(TokenType.lessThan)) {
        tsParseTypeArguments();
    }
}
function tsParseImportType() {
    expect(TokenType._import);
    expect(TokenType.parenL);
    expect(TokenType.string);
    expect(TokenType.parenR);
    if (eat(TokenType.dot)) {
        tsParseEntityName();
    }
    if (match(TokenType.lessThan)) {
        tsParseTypeArguments();
    }
}
function tsParseTypeParameter() {
    eat(TokenType._const);
    const hadIn = eat(TokenType._in);
    const hadOut = eatContextual(ContextualKeyword._out);
    eat(TokenType._const);
    if ((hadIn || hadOut) && !match(TokenType.name)) {
        // The "in" or "out" keyword must have actually been the type parameter
        // name, so set it as the name.
        state.tokens[state.tokens.length - 1].type = TokenType.name;
    }
    else {
        parseIdentifier();
    }
    if (eat(TokenType._extends)) {
        tsParseType();
    }
    if (eat(TokenType.eq)) {
        tsParseType();
    }
}
function tsTryParseTypeParameters() {
    if (match(TokenType.lessThan)) {
        tsParseTypeParameters();
    }
}
function tsParseTypeParameters() {
    const oldIsType = pushTypeContext(0);
    if (match(TokenType.lessThan) || match(TokenType.typeParameterStart)) {
        next();
    }
    else {
        unexpected();
    }
    while (!eat(TokenType.greaterThan) && !state.error) {
        tsParseTypeParameter();
        eat(TokenType.comma);
    }
    popTypeContext(oldIsType);
}
// Note: In TypeScript implementation we must provide `yieldContext` and `awaitContext`,
// but here it's always false, because this is only used for types.
function tsFillSignature(returnToken) {
    // Arrow fns *must* have return token (`=>`). Normal functions can omit it.
    const returnTokenRequired = returnToken === TokenType.arrow;
    tsTryParseTypeParameters();
    expect(TokenType.parenL);
    // Create a scope even though we're doing type parsing so we don't accidentally
    // treat params as top-level bindings.
    state.scopeDepth++;
    tsParseBindingListForSignature(false /* isBlockScope */);
    state.scopeDepth--;
    if (returnTokenRequired) {
        tsParseTypeOrTypePredicateAnnotation(returnToken);
    }
    else if (match(returnToken)) {
        tsParseTypeOrTypePredicateAnnotation(returnToken);
    }
}
function tsParseBindingListForSignature(isBlockScope) {
    parseBindingList(TokenType.parenR, isBlockScope);
}
function tsParseTypeMemberSemicolon() {
    if (!eat(TokenType.comma)) {
        semicolon();
    }
}
function tsParseSignatureMember() {
    tsFillSignature(TokenType.colon);
    tsParseTypeMemberSemicolon();
}
function tsIsUnambiguouslyIndexSignature() {
    const snapshot = state.snapshot();
    next(); // Skip '{'
    const isIndexSignature = eat(TokenType.name) && match(TokenType.colon);
    state.restoreFromSnapshot(snapshot);
    return isIndexSignature;
}
function tsTryParseIndexSignature() {
    if (!(match(TokenType.bracketL) && tsIsUnambiguouslyIndexSignature())) {
        return false;
    }
    const oldIsType = pushTypeContext(0);
    expect(TokenType.bracketL);
    parseIdentifier();
    tsParseTypeAnnotation();
    expect(TokenType.bracketR);
    tsTryParseTypeAnnotation();
    tsParseTypeMemberSemicolon();
    popTypeContext(oldIsType);
    return true;
}
function tsParsePropertyOrMethodSignature(isReadonly) {
    eat(TokenType.question);
    if (!isReadonly && (match(TokenType.parenL) || match(TokenType.lessThan))) {
        tsFillSignature(TokenType.colon);
        tsParseTypeMemberSemicolon();
    }
    else {
        tsTryParseTypeAnnotation();
        tsParseTypeMemberSemicolon();
    }
}
function tsParseTypeMember() {
    if (match(TokenType.parenL) || match(TokenType.lessThan)) {
        // call signature
        tsParseSignatureMember();
        return;
    }
    if (match(TokenType._new)) {
        next();
        if (match(TokenType.parenL) || match(TokenType.lessThan)) {
            // constructor signature
            tsParseSignatureMember();
        }
        else {
            tsParsePropertyOrMethodSignature(false);
        }
        return;
    }
    const readonly = !!tsParseModifier([ContextualKeyword._readonly]);
    const found = tsTryParseIndexSignature();
    if (found) {
        return;
    }
    if ((isContextual(ContextualKeyword._get) || isContextual(ContextualKeyword._set)) &&
        tsNextTokenCanFollowModifier()) ;
    parsePropertyName(-1 /* Types don't need context IDs. */);
    tsParsePropertyOrMethodSignature(readonly);
}
function tsParseTypeLiteral() {
    tsParseObjectTypeMembers();
}
function tsParseObjectTypeMembers() {
    expect(TokenType.braceL);
    while (!eat(TokenType.braceR) && !state.error) {
        tsParseTypeMember();
    }
}
function tsLookaheadIsStartOfMappedType() {
    const snapshot = state.snapshot();
    const isStartOfMappedType = tsIsStartOfMappedType();
    state.restoreFromSnapshot(snapshot);
    return isStartOfMappedType;
}
function tsIsStartOfMappedType() {
    next();
    if (eat(TokenType.plus) || eat(TokenType.minus)) {
        return isContextual(ContextualKeyword._readonly);
    }
    if (isContextual(ContextualKeyword._readonly)) {
        next();
    }
    if (!match(TokenType.bracketL)) {
        return false;
    }
    next();
    if (!tsIsIdentifier()) {
        return false;
    }
    next();
    return match(TokenType._in);
}
function tsParseMappedTypeParameter() {
    parseIdentifier();
    expect(TokenType._in);
    tsParseType();
}
function tsParseMappedType() {
    expect(TokenType.braceL);
    if (match(TokenType.plus) || match(TokenType.minus)) {
        next();
        expectContextual(ContextualKeyword._readonly);
    }
    else {
        eatContextual(ContextualKeyword._readonly);
    }
    expect(TokenType.bracketL);
    tsParseMappedTypeParameter();
    if (eatContextual(ContextualKeyword._as)) {
        tsParseType();
    }
    expect(TokenType.bracketR);
    if (match(TokenType.plus) || match(TokenType.minus)) {
        next();
        expect(TokenType.question);
    }
    else {
        eat(TokenType.question);
    }
    tsTryParseType();
    semicolon();
    expect(TokenType.braceR);
}
function tsParseTupleType() {
    expect(TokenType.bracketL);
    while (!eat(TokenType.bracketR) && !state.error) {
        // Do not validate presence of either none or only labeled elements
        tsParseTupleElementType();
        eat(TokenType.comma);
    }
}
function tsParseTupleElementType() {
    // parses `...TsType[]`
    if (eat(TokenType.ellipsis)) {
        tsParseType();
    }
    else {
        // parses `TsType?`
        tsParseType();
        eat(TokenType.question);
    }
    // The type we parsed above was actually a label
    if (eat(TokenType.colon)) {
        // Labeled tuple types must affix the label with `...` or `?`, so no need to handle those here
        tsParseType();
    }
}
function tsParseParenthesizedType() {
    expect(TokenType.parenL);
    tsParseType();
    expect(TokenType.parenR);
}
function tsParseTemplateLiteralType() {
    // Finish `, read quasi
    nextTemplateToken();
    // Finish quasi, read ${
    nextTemplateToken();
    while (!match(TokenType.backQuote) && !state.error) {
        expect(TokenType.dollarBraceL);
        tsParseType();
        // Finish }, read quasi
        nextTemplateToken();
        // Finish quasi, read either ${ or `
        nextTemplateToken();
    }
    next();
}
var FunctionType;
(function (FunctionType) {
    FunctionType[FunctionType["TSFunctionType"] = 0] = "TSFunctionType";
    FunctionType[FunctionType["TSConstructorType"] = 1] = "TSConstructorType";
    FunctionType[FunctionType["TSAbstractConstructorType"] = 2] = "TSAbstractConstructorType";
})(FunctionType || (FunctionType = {}));
function tsParseFunctionOrConstructorType(type) {
    if (type === FunctionType.TSAbstractConstructorType) {
        expectContextual(ContextualKeyword._abstract);
    }
    if (type === FunctionType.TSConstructorType || type === FunctionType.TSAbstractConstructorType) {
        expect(TokenType._new);
    }
    const oldInDisallowConditionalTypesContext = state.inDisallowConditionalTypesContext;
    state.inDisallowConditionalTypesContext = false;
    tsFillSignature(TokenType.arrow);
    state.inDisallowConditionalTypesContext = oldInDisallowConditionalTypesContext;
}
function tsParseNonArrayType() {
    switch (state.type) {
        case TokenType.name:
            tsParseTypeReference();
            return;
        case TokenType._void:
        case TokenType._null:
            next();
            return;
        case TokenType.string:
        case TokenType.num:
        case TokenType.bigint:
        case TokenType.decimal:
        case TokenType._true:
        case TokenType._false:
            parseLiteral();
            return;
        case TokenType.minus:
            next();
            parseLiteral();
            return;
        case TokenType._this: {
            tsParseThisTypeNode();
            if (isContextual(ContextualKeyword._is) && !hasPrecedingLineBreak()) {
                tsParseThisTypePredicate();
            }
            return;
        }
        case TokenType._typeof:
            tsParseTypeQuery();
            return;
        case TokenType._import:
            tsParseImportType();
            return;
        case TokenType.braceL:
            if (tsLookaheadIsStartOfMappedType()) {
                tsParseMappedType();
            }
            else {
                tsParseTypeLiteral();
            }
            return;
        case TokenType.bracketL:
            tsParseTupleType();
            return;
        case TokenType.parenL:
            tsParseParenthesizedType();
            return;
        case TokenType.backQuote:
            tsParseTemplateLiteralType();
            return;
        default:
            if (state.type & TokenType.IS_KEYWORD) {
                next();
                state.tokens[state.tokens.length - 1].type = TokenType.name;
                return;
            }
            break;
    }
    unexpected();
}
function tsParseArrayTypeOrHigher() {
    tsParseNonArrayType();
    while (!hasPrecedingLineBreak() && eat(TokenType.bracketL)) {
        if (!eat(TokenType.bracketR)) {
            // If we hit ] immediately, this is an array type, otherwise it's an indexed access type.
            tsParseType();
            expect(TokenType.bracketR);
        }
    }
}
function tsParseInferType() {
    expectContextual(ContextualKeyword._infer);
    parseIdentifier();
    if (match(TokenType._extends)) {
        // Infer type constraints introduce an ambiguity about whether the "extends"
        // is a constraint for this infer type or is another conditional type.
        const snapshot = state.snapshot();
        expect(TokenType._extends);
        const oldInDisallowConditionalTypesContext = state.inDisallowConditionalTypesContext;
        state.inDisallowConditionalTypesContext = true;
        tsParseType();
        state.inDisallowConditionalTypesContext = oldInDisallowConditionalTypesContext;
        if (state.error || (!state.inDisallowConditionalTypesContext && match(TokenType.question))) {
            state.restoreFromSnapshot(snapshot);
        }
    }
}
function tsParseTypeOperatorOrHigher() {
    if (isContextual(ContextualKeyword._keyof) ||
        isContextual(ContextualKeyword._unique) ||
        isContextual(ContextualKeyword._readonly)) {
        next();
        tsParseTypeOperatorOrHigher();
    }
    else if (isContextual(ContextualKeyword._infer)) {
        tsParseInferType();
    }
    else {
        const oldInDisallowConditionalTypesContext = state.inDisallowConditionalTypesContext;
        state.inDisallowConditionalTypesContext = false;
        tsParseArrayTypeOrHigher();
        state.inDisallowConditionalTypesContext = oldInDisallowConditionalTypesContext;
    }
}
function tsParseIntersectionTypeOrHigher() {
    eat(TokenType.bitwiseAND);
    tsParseTypeOperatorOrHigher();
    if (match(TokenType.bitwiseAND)) {
        while (eat(TokenType.bitwiseAND)) {
            tsParseTypeOperatorOrHigher();
        }
    }
}
function tsParseUnionTypeOrHigher() {
    eat(TokenType.bitwiseOR);
    tsParseIntersectionTypeOrHigher();
    if (match(TokenType.bitwiseOR)) {
        while (eat(TokenType.bitwiseOR)) {
            tsParseIntersectionTypeOrHigher();
        }
    }
}
function tsIsStartOfFunctionType() {
    if (match(TokenType.lessThan)) {
        return true;
    }
    return match(TokenType.parenL) && tsLookaheadIsUnambiguouslyStartOfFunctionType();
}
function tsSkipParameterStart() {
    if (match(TokenType.name) || match(TokenType._this)) {
        next();
        return true;
    }
    // If this is a possible array/object destructure, walk to the matching bracket/brace.
    // The next token after will tell us definitively whether this is a function param.
    if (match(TokenType.braceL) || match(TokenType.bracketL)) {
        let depth = 1;
        next();
        while (depth > 0 && !state.error) {
            if (match(TokenType.braceL) || match(TokenType.bracketL)) {
                depth++;
            }
            else if (match(TokenType.braceR) || match(TokenType.bracketR)) {
                depth--;
            }
            next();
        }
        return true;
    }
    return false;
}
function tsLookaheadIsUnambiguouslyStartOfFunctionType() {
    const snapshot = state.snapshot();
    const isUnambiguouslyStartOfFunctionType = tsIsUnambiguouslyStartOfFunctionType();
    state.restoreFromSnapshot(snapshot);
    return isUnambiguouslyStartOfFunctionType;
}
function tsIsUnambiguouslyStartOfFunctionType() {
    next();
    if (match(TokenType.parenR) || match(TokenType.ellipsis)) {
        // ( )
        // ( ...
        return true;
    }
    if (tsSkipParameterStart()) {
        if (match(TokenType.colon) || match(TokenType.comma) || match(TokenType.question) || match(TokenType.eq)) {
            // ( xxx :
            // ( xxx ,
            // ( xxx ?
            // ( xxx =
            return true;
        }
        if (match(TokenType.parenR)) {
            next();
            if (match(TokenType.arrow)) {
                // ( xxx ) =>
                return true;
            }
        }
    }
    return false;
}
function tsParseTypeOrTypePredicateAnnotation(returnToken) {
    const oldIsType = pushTypeContext(0);
    expect(returnToken);
    const finishedReturn = tsParseTypePredicateOrAssertsPrefix();
    if (!finishedReturn) {
        tsParseType();
    }
    popTypeContext(oldIsType);
}
function tsTryParseTypeOrTypePredicateAnnotation() {
    if (match(TokenType.colon)) {
        tsParseTypeOrTypePredicateAnnotation(TokenType.colon);
    }
}
function tsTryParseTypeAnnotation() {
    if (match(TokenType.colon)) {
        tsParseTypeAnnotation();
    }
}
function tsTryParseType() {
    if (eat(TokenType.colon)) {
        tsParseType();
    }
}
/**
 * Detect a few special return syntax cases: `x is T`, `asserts x`, `asserts x is T`,
 * `asserts this is T`.
 *
 * Returns true if we parsed the return type, false if there's still a type to be parsed.
 */
function tsParseTypePredicateOrAssertsPrefix() {
    const snapshot = state.snapshot();
    if (isContextual(ContextualKeyword._asserts)) {
        // Normally this is `asserts x is T`, but at this point, it might be `asserts is T` (a user-
        // defined type guard on the `asserts` variable) or just a type called `asserts`.
        next();
        if (eatContextual(ContextualKeyword._is)) {
            // If we see `asserts is`, then this must be of the form `asserts is T`, since
            // `asserts is is T` isn't valid.
            tsParseType();
            return true;
        }
        else if (tsIsIdentifier() || match(TokenType._this)) {
            next();
            if (eatContextual(ContextualKeyword._is)) {
                // If we see `is`, then this is `asserts x is T`. Otherwise, it's `asserts x`.
                tsParseType();
            }
            return true;
        }
        else {
            // Regular type, so bail out and start type parsing from scratch.
            state.restoreFromSnapshot(snapshot);
            return false;
        }
    }
    else if (tsIsIdentifier() || match(TokenType._this)) {
        // This is a regular identifier, which may or may not have "is" after it.
        next();
        if (isContextual(ContextualKeyword._is) && !hasPrecedingLineBreak()) {
            next();
            tsParseType();
            return true;
        }
        else {
            // Regular type, so bail out and start type parsing from scratch.
            state.restoreFromSnapshot(snapshot);
            return false;
        }
    }
    return false;
}
function tsParseTypeAnnotation() {
    const oldIsType = pushTypeContext(0);
    expect(TokenType.colon);
    tsParseType();
    popTypeContext(oldIsType);
}
function tsParseType() {
    tsParseNonConditionalType();
    if (state.inDisallowConditionalTypesContext || hasPrecedingLineBreak() || !eat(TokenType._extends)) {
        return;
    }
    // extends type
    const oldInDisallowConditionalTypesContext = state.inDisallowConditionalTypesContext;
    state.inDisallowConditionalTypesContext = true;
    tsParseNonConditionalType();
    state.inDisallowConditionalTypesContext = oldInDisallowConditionalTypesContext;
    expect(TokenType.question);
    // true type
    tsParseType();
    expect(TokenType.colon);
    // false type
    tsParseType();
}
function isAbstractConstructorSignature() {
    return isContextual(ContextualKeyword._abstract) && lookaheadType() === TokenType._new;
}
function tsParseNonConditionalType() {
    if (tsIsStartOfFunctionType()) {
        tsParseFunctionOrConstructorType(FunctionType.TSFunctionType);
        return;
    }
    if (match(TokenType._new)) {
        // As in `new () => Date`
        tsParseFunctionOrConstructorType(FunctionType.TSConstructorType);
        return;
    }
    else if (isAbstractConstructorSignature()) {
        // As in `abstract new () => Date`
        tsParseFunctionOrConstructorType(FunctionType.TSAbstractConstructorType);
        return;
    }
    tsParseUnionTypeOrHigher();
}
function tsParseTypeAssertion() {
    const oldIsType = pushTypeContext(1);
    tsParseType();
    expect(TokenType.greaterThan);
    popTypeContext(oldIsType);
    parseMaybeUnary();
}
function tsTryParseJSXTypeArgument() {
    if (eat(TokenType.jsxTagStart)) {
        state.tokens[state.tokens.length - 1].type = TokenType.typeParameterStart;
        const oldIsType = pushTypeContext(1);
        while (!match(TokenType.greaterThan) && !state.error) {
            tsParseType();
            eat(TokenType.comma);
        }
        // Process >, but the one after needs to be parsed JSX-style.
        nextJSXTagToken();
        popTypeContext(oldIsType);
    }
}
function tsParseHeritageClause() {
    while (!match(TokenType.braceL) && !state.error) {
        tsParseExpressionWithTypeArguments();
        eat(TokenType.comma);
    }
}
function tsParseExpressionWithTypeArguments() {
    // Note: TS uses parseLeftHandSideExpressionOrHigher,
    // then has grammar errors later if it's not an EntityName.
    tsParseEntityName();
    if (match(TokenType.lessThan)) {
        tsParseTypeArguments();
    }
}
function tsParseInterfaceDeclaration() {
    parseBindingIdentifier(false);
    tsTryParseTypeParameters();
    if (eat(TokenType._extends)) {
        tsParseHeritageClause();
    }
    tsParseObjectTypeMembers();
}
function tsParseTypeAliasDeclaration() {
    parseBindingIdentifier(false);
    tsTryParseTypeParameters();
    expect(TokenType.eq);
    tsParseType();
    semicolon();
}
function tsParseEnumMember() {
    // Computed property names are grammar errors in an enum, so accept just string literal or identifier.
    if (match(TokenType.string)) {
        parseLiteral();
    }
    else {
        parseIdentifier();
    }
    if (eat(TokenType.eq)) {
        const eqIndex = state.tokens.length - 1;
        parseMaybeAssign();
        state.tokens[eqIndex].rhsEndIndex = state.tokens.length;
    }
}
function tsParseEnumDeclaration() {
    parseBindingIdentifier(false);
    expect(TokenType.braceL);
    while (!eat(TokenType.braceR) && !state.error) {
        tsParseEnumMember();
        eat(TokenType.comma);
    }
}
function tsParseModuleBlock() {
    expect(TokenType.braceL);
    parseBlockBody(/* end */ TokenType.braceR);
}
function tsParseModuleOrNamespaceDeclaration() {
    parseBindingIdentifier(false);
    if (eat(TokenType.dot)) {
        tsParseModuleOrNamespaceDeclaration();
    }
    else {
        tsParseModuleBlock();
    }
}
function tsParseAmbientExternalModuleDeclaration() {
    if (isContextual(ContextualKeyword._global)) {
        parseIdentifier();
    }
    else if (match(TokenType.string)) {
        parseExprAtom();
    }
    else {
        unexpected();
    }
    if (match(TokenType.braceL)) {
        tsParseModuleBlock();
    }
    else {
        semicolon();
    }
}
function tsParseImportEqualsDeclaration() {
    parseImportedIdentifier();
    expect(TokenType.eq);
    tsParseModuleReference();
    semicolon();
}
function tsIsExternalModuleReference() {
    return isContextual(ContextualKeyword._require) && lookaheadType() === TokenType.parenL;
}
function tsParseModuleReference() {
    if (tsIsExternalModuleReference()) {
        tsParseExternalModuleReference();
    }
    else {
        tsParseEntityName();
    }
}
function tsParseExternalModuleReference() {
    expectContextual(ContextualKeyword._require);
    expect(TokenType.parenL);
    if (!match(TokenType.string)) {
        unexpected();
    }
    parseLiteral();
    expect(TokenType.parenR);
}
// Utilities
// Returns true if a statement matched.
function tsTryParseDeclare() {
    if (isLineTerminator()) {
        return false;
    }
    switch (state.type) {
        case TokenType._function: {
            const oldIsType = pushTypeContext(1);
            next();
            // We don't need to precisely get the function start here, since it's only used to mark
            // the function as a type if it's bodiless, and it's already a type here.
            const functionStart = state.start;
            parseFunction(functionStart, /* isStatement */ true);
            popTypeContext(oldIsType);
            return true;
        }
        case TokenType._class: {
            const oldIsType = pushTypeContext(1);
            parseClass(/* isStatement */ true, /* optionalId */ false);
            popTypeContext(oldIsType);
            return true;
        }
        case TokenType._const: {
            if (match(TokenType._const) && isLookaheadContextual(ContextualKeyword._enum)) {
                const oldIsType = pushTypeContext(1);
                // `const enum = 0;` not allowed because "enum" is a strict mode reserved word.
                expect(TokenType._const);
                expectContextual(ContextualKeyword._enum);
                state.tokens[state.tokens.length - 1].type = TokenType._enum;
                tsParseEnumDeclaration();
                popTypeContext(oldIsType);
                return true;
            }
        }
        // falls through
        case TokenType._var:
        case TokenType._let: {
            const oldIsType = pushTypeContext(1);
            parseVarStatement(state.type !== TokenType._var);
            popTypeContext(oldIsType);
            return true;
        }
        case TokenType.name: {
            const oldIsType = pushTypeContext(1);
            const contextualKeyword = state.contextualKeyword;
            let matched = false;
            if (contextualKeyword === ContextualKeyword._global) {
                tsParseAmbientExternalModuleDeclaration();
                matched = true;
            }
            else {
                matched = tsParseDeclaration(contextualKeyword, /* isBeforeToken */ true);
            }
            popTypeContext(oldIsType);
            return matched;
        }
        default:
            return false;
    }
}
// Note: this won't be called unless the keyword is allowed in `shouldParseExportDeclaration`.
// Returns true if it matched a declaration.
function tsTryParseExportDeclaration() {
    return tsParseDeclaration(state.contextualKeyword, /* isBeforeToken */ true);
}
// Returns true if it matched a statement.
function tsParseExpressionStatement(contextualKeyword) {
    switch (contextualKeyword) {
        case ContextualKeyword._declare: {
            const declareTokenIndex = state.tokens.length - 1;
            const matched = tsTryParseDeclare();
            if (matched) {
                state.tokens[declareTokenIndex].type = TokenType._declare;
                return true;
            }
            break;
        }
        case ContextualKeyword._global:
            // `global { }` (with no `declare`) may appear inside an ambient module declaration.
            // Would like to use tsParseAmbientExternalModuleDeclaration here, but already ran past "global".
            if (match(TokenType.braceL)) {
                tsParseModuleBlock();
                return true;
            }
            break;
        default:
            return tsParseDeclaration(contextualKeyword, /* isBeforeToken */ false);
    }
    return false;
}
/**
 * Common code for parsing a declaration.
 *
 * isBeforeToken indicates that the current parser state is at the contextual
 * keyword (and that it is not yet emitted) rather than reading the token after
 * it. When isBeforeToken is true, we may be preceded by an `export` token and
 * should include that token in a type context we create, e.g. to handle
 * `export interface` or `export type`. (This is a bit of a hack and should be
 * cleaned up at some point.)
 *
 * Returns true if it matched a declaration.
 */
function tsParseDeclaration(contextualKeyword, isBeforeToken) {
    switch (contextualKeyword) {
        case ContextualKeyword._abstract:
            if (tsCheckLineTerminator(isBeforeToken) && match(TokenType._class)) {
                state.tokens[state.tokens.length - 1].type = TokenType._abstract;
                parseClass(/* isStatement */ true, /* optionalId */ false);
                return true;
            }
            break;
        case ContextualKeyword._enum:
            if (tsCheckLineTerminator(isBeforeToken) && match(TokenType.name)) {
                state.tokens[state.tokens.length - 1].type = TokenType._enum;
                tsParseEnumDeclaration();
                return true;
            }
            break;
        case ContextualKeyword._interface:
            if (tsCheckLineTerminator(isBeforeToken) && match(TokenType.name)) {
                // `next` is true in "export" and "declare" contexts, so we want to remove that token
                // as well.
                const oldIsType = pushTypeContext(isBeforeToken ? 2 : 1);
                tsParseInterfaceDeclaration();
                popTypeContext(oldIsType);
                return true;
            }
            break;
        case ContextualKeyword._module:
            if (tsCheckLineTerminator(isBeforeToken)) {
                if (match(TokenType.string)) {
                    const oldIsType = pushTypeContext(isBeforeToken ? 2 : 1);
                    tsParseAmbientExternalModuleDeclaration();
                    popTypeContext(oldIsType);
                    return true;
                }
                else if (match(TokenType.name)) {
                    const oldIsType = pushTypeContext(isBeforeToken ? 2 : 1);
                    tsParseModuleOrNamespaceDeclaration();
                    popTypeContext(oldIsType);
                    return true;
                }
            }
            break;
        case ContextualKeyword._namespace:
            if (tsCheckLineTerminator(isBeforeToken) && match(TokenType.name)) {
                const oldIsType = pushTypeContext(isBeforeToken ? 2 : 1);
                tsParseModuleOrNamespaceDeclaration();
                popTypeContext(oldIsType);
                return true;
            }
            break;
        case ContextualKeyword._type:
            if (tsCheckLineTerminator(isBeforeToken) && match(TokenType.name)) {
                const oldIsType = pushTypeContext(isBeforeToken ? 2 : 1);
                tsParseTypeAliasDeclaration();
                popTypeContext(oldIsType);
                return true;
            }
            break;
    }
    return false;
}
function tsCheckLineTerminator(isBeforeToken) {
    if (isBeforeToken) {
        // Babel checks hasFollowingLineBreak here and returns false, but this
        // doesn't actually come up, e.g. `export interface` can never be on its own
        // line in valid code.
        next();
        return true;
    }
    else {
        return !isLineTerminator();
    }
}
// Returns true if there was a generic async arrow function.
function tsTryParseGenericAsyncArrowFunction() {
    const snapshot = state.snapshot();
    tsParseTypeParameters();
    parseFunctionParams();
    tsTryParseTypeOrTypePredicateAnnotation();
    expect(TokenType.arrow);
    if (state.error) {
        state.restoreFromSnapshot(snapshot);
        return false;
    }
    parseFunctionBody(true);
    return true;
}
/**
 * If necessary, hack the tokenizer state so that this bitshift was actually a
 * less-than token, then keep parsing. This should only be used in situations
 * where we restore from snapshot on error (which reverts this change) or
 * where bitshift would be illegal anyway (e.g. in a class "extends" clause).
 *
 * This hack is useful to handle situations like foo<<T>() => void>() where
 * there can legitimately be two open-angle-brackets in a row in TS.
 */
function tsParseTypeArgumentsWithPossibleBitshift() {
    if (state.type === TokenType.bitShiftL) {
        state.pos -= 1;
        finishToken(TokenType.lessThan);
    }
    tsParseTypeArguments();
}
function tsParseTypeArguments() {
    const oldIsType = pushTypeContext(0);
    expect(TokenType.lessThan);
    while (!match(TokenType.greaterThan) && !state.error) {
        tsParseType();
        eat(TokenType.comma);
    }
    if (!oldIsType) {
        // If the type arguments are present in an expression context, e.g.
        // f<number>(), then the > sign should be tokenized as a non-type token.
        // In particular, f(a < b, c >= d) should parse the >= as a single token,
        // resulting in a syntax error and fallback to the non-type-args
        // interpretation. In the success case, even though the > is tokenized as a
        // non-type token, it still must be marked as a type token so that it is
        // erased.
        popTypeContext(oldIsType);
        rescan_gt();
        expect(TokenType.greaterThan);
        state.tokens[state.tokens.length - 1].isType = true;
    }
    else {
        expect(TokenType.greaterThan);
        popTypeContext(oldIsType);
    }
}
function tsIsDeclarationStart() {
    if (match(TokenType.name)) {
        switch (state.contextualKeyword) {
            case ContextualKeyword._abstract:
            case ContextualKeyword._declare:
            case ContextualKeyword._enum:
            case ContextualKeyword._interface:
            case ContextualKeyword._module:
            case ContextualKeyword._namespace:
            case ContextualKeyword._type:
                return true;
        }
    }
    return false;
}
// ======================================================
// OVERRIDES
// ======================================================
function tsParseFunctionBodyAndFinish(functionStart, funcContextId) {
    // For arrow functions, `parseArrow` handles the return type itself.
    if (match(TokenType.colon)) {
        tsParseTypeOrTypePredicateAnnotation(TokenType.colon);
    }
    // The original code checked the node type to make sure this function type allows a missing
    // body, but we skip that to avoid sending around the node type. We instead just use the
    // allowExpressionBody boolean to make sure it's not an arrow function.
    if (!match(TokenType.braceL) && isLineTerminator()) {
        // Retroactively mark the function declaration as a type.
        let i = state.tokens.length - 1;
        while (i >= 0 &&
            (state.tokens[i].start >= functionStart ||
                state.tokens[i].type === TokenType._default ||
                state.tokens[i].type === TokenType._export)) {
            state.tokens[i].isType = true;
            i--;
        }
        return;
    }
    parseFunctionBody(false, funcContextId);
}
function tsParseSubscript(startTokenIndex, noCalls, stopState) {
    if (!hasPrecedingLineBreak() && eat(TokenType.bang)) {
        state.tokens[state.tokens.length - 1].type = TokenType.nonNullAssertion;
        return;
    }
    if (match(TokenType.lessThan) || match(TokenType.bitShiftL)) {
        // There are number of things we are going to "maybe" parse, like type arguments on
        // tagged template expressions. If any of them fail, walk it back and continue.
        const snapshot = state.snapshot();
        if (!noCalls && atPossibleAsync()) {
            // Almost certainly this is a generic async function `async <T>() => ...
            // But it might be a call with a type argument `async<T>();`
            const asyncArrowFn = tsTryParseGenericAsyncArrowFunction();
            if (asyncArrowFn) {
                return;
            }
        }
        tsParseTypeArgumentsWithPossibleBitshift();
        if (!noCalls && eat(TokenType.parenL)) {
            // With f<T>(), the subscriptStartIndex marker is on the ( token.
            state.tokens[state.tokens.length - 1].subscriptStartIndex = startTokenIndex;
            parseCallExpressionArguments();
        }
        else if (match(TokenType.backQuote)) {
            // Tagged template with a type argument.
            parseTemplate();
        }
        else if (
        // The remaining possible case is an instantiation expression, e.g.
        // Array<number> . Check for a few cases that would disqualify it and
        // cause us to bail out.
        // a<b>>c is not (a<b>)>c, but a<(b>>c)
        state.type === TokenType.greaterThan ||
            // a<b>c is (a<b)>c
            (state.type !== TokenType.parenL &&
                Boolean(state.type & TokenType.IS_EXPRESSION_START) &&
                !hasPrecedingLineBreak())) {
            // Bail out. We have something like a<b>c, which is not an expression with
            // type arguments but an (a < b) > c comparison.
            unexpected();
        }
        if (state.error) {
            state.restoreFromSnapshot(snapshot);
        }
        else {
            return;
        }
    }
    else if (!noCalls && match(TokenType.questionDot) && lookaheadType() === TokenType.lessThan) {
        // If we see f?.<, then this must be an optional call with a type argument.
        next();
        state.tokens[startTokenIndex].isOptionalChainStart = true;
        // With f?.<T>(), the subscriptStartIndex marker is on the ?. token.
        state.tokens[state.tokens.length - 1].subscriptStartIndex = startTokenIndex;
        tsParseTypeArguments();
        expect(TokenType.parenL);
        parseCallExpressionArguments();
    }
    baseParseSubscript(startTokenIndex, noCalls, stopState);
}
function tsTryParseExport() {
    if (eat(TokenType._import)) {
        // One of these cases:
        // export import A = B;
        // export import type A = require("A");
        if (isContextual(ContextualKeyword._type) && lookaheadType() !== TokenType.eq) {
            // Eat a `type` token, unless it's actually an identifier name.
            expectContextual(ContextualKeyword._type);
        }
        tsParseImportEqualsDeclaration();
        return true;
    }
    else if (eat(TokenType.eq)) {
        // `export = x;`
        parseExpression();
        semicolon();
        return true;
    }
    else if (eatContextual(ContextualKeyword._as)) {
        // `export as namespace A;`
        // See `parseNamespaceExportDeclaration` in TypeScript's own parser
        expectContextual(ContextualKeyword._namespace);
        parseIdentifier();
        semicolon();
        return true;
    }
    else {
        if (isContextual(ContextualKeyword._type)) {
            const nextType = lookaheadType();
            // export type {foo} from 'a';
            // export type * from 'a';'
            // export type * as ns from 'a';'
            if (nextType === TokenType.braceL || nextType === TokenType.star) {
                next();
            }
        }
        return false;
    }
}
/**
 * Parse a TS import specifier, which may be prefixed with "type" and may be of
 * the form `foo as bar`.
 *
 * The number of identifier-like tokens we see happens to be enough to uniquely
 * identify the form, so simply count the number of identifiers rather than
 * matching the words `type` or `as`. This is particularly important because
 * `type` and `as` could each actually be plain identifiers rather than
 * keywords.
 */
function tsParseImportSpecifier() {
    parseIdentifier();
    if (match(TokenType.comma) || match(TokenType.braceR)) {
        // import {foo}
        state.tokens[state.tokens.length - 1].identifierRole = IdentifierRole.ImportDeclaration;
        return;
    }
    parseIdentifier();
    if (match(TokenType.comma) || match(TokenType.braceR)) {
        // import {type foo}
        state.tokens[state.tokens.length - 1].identifierRole = IdentifierRole.ImportDeclaration;
        state.tokens[state.tokens.length - 2].isType = true;
        state.tokens[state.tokens.length - 1].isType = true;
        return;
    }
    parseIdentifier();
    if (match(TokenType.comma) || match(TokenType.braceR)) {
        // import {foo as bar}
        state.tokens[state.tokens.length - 3].identifierRole = IdentifierRole.ImportAccess;
        state.tokens[state.tokens.length - 1].identifierRole = IdentifierRole.ImportDeclaration;
        return;
    }
    parseIdentifier();
    // import {type foo as bar}
    state.tokens[state.tokens.length - 3].identifierRole = IdentifierRole.ImportAccess;
    state.tokens[state.tokens.length - 1].identifierRole = IdentifierRole.ImportDeclaration;
    state.tokens[state.tokens.length - 4].isType = true;
    state.tokens[state.tokens.length - 3].isType = true;
    state.tokens[state.tokens.length - 2].isType = true;
    state.tokens[state.tokens.length - 1].isType = true;
}
/**
 * Just like named import specifiers, export specifiers can have from 1 to 4
 * tokens, inclusive, and the number of tokens determines the role of each token.
 */
function tsParseExportSpecifier() {
    parseIdentifier();
    if (match(TokenType.comma) || match(TokenType.braceR)) {
        // export {foo}
        state.tokens[state.tokens.length - 1].identifierRole = IdentifierRole.ExportAccess;
        return;
    }
    parseIdentifier();
    if (match(TokenType.comma) || match(TokenType.braceR)) {
        // export {type foo}
        state.tokens[state.tokens.length - 1].identifierRole = IdentifierRole.ExportAccess;
        state.tokens[state.tokens.length - 2].isType = true;
        state.tokens[state.tokens.length - 1].isType = true;
        return;
    }
    parseIdentifier();
    if (match(TokenType.comma) || match(TokenType.braceR)) {
        // export {foo as bar}
        state.tokens[state.tokens.length - 3].identifierRole = IdentifierRole.ExportAccess;
        return;
    }
    parseIdentifier();
    // export {type foo as bar}
    state.tokens[state.tokens.length - 3].identifierRole = IdentifierRole.ExportAccess;
    state.tokens[state.tokens.length - 4].isType = true;
    state.tokens[state.tokens.length - 3].isType = true;
    state.tokens[state.tokens.length - 2].isType = true;
    state.tokens[state.tokens.length - 1].isType = true;
}
function tsTryParseExportDefaultExpression() {
    if (isContextual(ContextualKeyword._abstract) && lookaheadType() === TokenType._class) {
        state.type = TokenType._abstract;
        next(); // Skip "abstract"
        parseClass(true, true);
        return true;
    }
    if (isContextual(ContextualKeyword._interface)) {
        // Make sure "export default" are considered type tokens so the whole thing is removed.
        const oldIsType = pushTypeContext(2);
        tsParseDeclaration(ContextualKeyword._interface, true);
        popTypeContext(oldIsType);
        return true;
    }
    return false;
}
function tsTryParseStatementContent() {
    if (state.type === TokenType._const) {
        const ahead = lookaheadTypeAndKeyword();
        if (ahead.type === TokenType.name && ahead.contextualKeyword === ContextualKeyword._enum) {
            expect(TokenType._const);
            expectContextual(ContextualKeyword._enum);
            state.tokens[state.tokens.length - 1].type = TokenType._enum;
            tsParseEnumDeclaration();
            return true;
        }
    }
    return false;
}
function tsTryParseClassMemberWithIsStatic(isStatic) {
    const memberStartIndexAfterStatic = state.tokens.length;
    tsParseModifiers([
        ContextualKeyword._abstract,
        ContextualKeyword._readonly,
        ContextualKeyword._declare,
        ContextualKeyword._static,
        ContextualKeyword._override,
    ]);
    const modifiersEndIndex = state.tokens.length;
    const found = tsTryParseIndexSignature();
    if (found) {
        // Index signatures are type declarations, so set the modifier tokens as
        // type tokens. Most tokens could be assumed to be type tokens, but `static`
        // is ambiguous unless we set it explicitly here.
        const memberStartIndex = isStatic
            ? memberStartIndexAfterStatic - 1
            : memberStartIndexAfterStatic;
        for (let i = memberStartIndex; i < modifiersEndIndex; i++) {
            state.tokens[i].isType = true;
        }
        return true;
    }
    return false;
}
// Note: The reason we do this in `parseIdentifierStatement` and not `parseStatement`
// is that e.g. `type()` is valid JS, so we must try parsing that first.
// If it's really a type, we will parse `type` as the statement, and can correct it here
// by parsing the rest.
function tsParseIdentifierStatement(contextualKeyword) {
    const matched = tsParseExpressionStatement(contextualKeyword);
    if (!matched) {
        semicolon();
    }
}
function tsParseExportDeclaration() {
    // "export declare" is equivalent to just "export".
    const isDeclare = eatContextual(ContextualKeyword._declare);
    if (isDeclare) {
        state.tokens[state.tokens.length - 1].type = TokenType._declare;
    }
    let matchedDeclaration = false;
    if (match(TokenType.name)) {
        if (isDeclare) {
            const oldIsType = pushTypeContext(2);
            matchedDeclaration = tsTryParseExportDeclaration();
            popTypeContext(oldIsType);
        }
        else {
            matchedDeclaration = tsTryParseExportDeclaration();
        }
    }
    if (!matchedDeclaration) {
        if (isDeclare) {
            const oldIsType = pushTypeContext(2);
            parseStatement(true);
            popTypeContext(oldIsType);
        }
        else {
            parseStatement(true);
        }
    }
}
function tsAfterParseClassSuper(hasSuper) {
    if (hasSuper && (match(TokenType.lessThan) || match(TokenType.bitShiftL))) {
        tsParseTypeArgumentsWithPossibleBitshift();
    }
    if (eatContextual(ContextualKeyword._implements)) {
        state.tokens[state.tokens.length - 1].type = TokenType._implements;
        const oldIsType = pushTypeContext(1);
        tsParseHeritageClause();
        popTypeContext(oldIsType);
    }
}
function tsStartParseObjPropValue() {
    tsTryParseTypeParameters();
}
function tsStartParseFunctionParams() {
    tsTryParseTypeParameters();
}
// `let x: number;`
function tsAfterParseVarHead() {
    const oldIsType = pushTypeContext(0);
    if (!hasPrecedingLineBreak()) {
        eat(TokenType.bang);
    }
    tsTryParseTypeAnnotation();
    popTypeContext(oldIsType);
}
// parse the return type of an async arrow function - let foo = (async (): number => {});
function tsStartParseAsyncArrowFromCallExpression() {
    if (match(TokenType.colon)) {
        tsParseTypeAnnotation();
    }
}
// Returns true if the expression was an arrow function.
function tsParseMaybeAssign(noIn, isWithinParens) {
    // Note: When the JSX plugin is on, type assertions (`<T> x`) aren't valid syntax.
    if (isJSXEnabled) {
        return tsParseMaybeAssignWithJSX(noIn, isWithinParens);
    }
    else {
        return tsParseMaybeAssignWithoutJSX(noIn, isWithinParens);
    }
}
function tsParseMaybeAssignWithJSX(noIn, isWithinParens) {
    if (!match(TokenType.lessThan)) {
        return baseParseMaybeAssign(noIn, isWithinParens);
    }
    // Prefer to parse JSX if possible. But may be an arrow fn.
    const snapshot = state.snapshot();
    let wasArrow = baseParseMaybeAssign(noIn, isWithinParens);
    if (state.error) {
        state.restoreFromSnapshot(snapshot);
    }
    else {
        return wasArrow;
    }
    // Otherwise, try as type-parameterized arrow function.
    state.type = TokenType.typeParameterStart;
    // This is similar to TypeScript's `tryParseParenthesizedArrowFunctionExpression`.
    tsParseTypeParameters();
    wasArrow = baseParseMaybeAssign(noIn, isWithinParens);
    if (!wasArrow) {
        unexpected();
    }
    return wasArrow;
}
function tsParseMaybeAssignWithoutJSX(noIn, isWithinParens) {
    if (!match(TokenType.lessThan)) {
        return baseParseMaybeAssign(noIn, isWithinParens);
    }
    const snapshot = state.snapshot();
    // This is similar to TypeScript's `tryParseParenthesizedArrowFunctionExpression`.
    tsParseTypeParameters();
    const wasArrow = baseParseMaybeAssign(noIn, isWithinParens);
    if (!wasArrow) {
        unexpected();
    }
    if (state.error) {
        state.restoreFromSnapshot(snapshot);
    }
    else {
        return wasArrow;
    }
    // Try parsing a type cast instead of an arrow function.
    // This will start with a type assertion (via parseMaybeUnary).
    // But don't directly call `tsParseTypeAssertion` because we want to handle any binary after it.
    return baseParseMaybeAssign(noIn, isWithinParens);
}
function tsParseArrow() {
    if (match(TokenType.colon)) {
        // This is different from how the TS parser does it.
        // TS uses lookahead. Babylon parses it as a parenthesized expression and converts.
        const snapshot = state.snapshot();
        tsParseTypeOrTypePredicateAnnotation(TokenType.colon);
        if (canInsertSemicolon())
            unexpected();
        if (!match(TokenType.arrow))
            unexpected();
        if (state.error) {
            state.restoreFromSnapshot(snapshot);
        }
    }
    return eat(TokenType.arrow);
}
// Allow type annotations inside of a parameter list.
function tsParseAssignableListItemTypes() {
    const oldIsType = pushTypeContext(0);
    eat(TokenType.question);
    tsTryParseTypeAnnotation();
    popTypeContext(oldIsType);
}
function tsParseMaybeDecoratorArguments() {
    if (match(TokenType.lessThan) || match(TokenType.bitShiftL)) {
        tsParseTypeArgumentsWithPossibleBitshift();
    }
    baseParseMaybeDecoratorArguments();
}

/**
 * Read token with JSX contents.
 *
 * In addition to detecting jsxTagStart and also regular tokens that might be
 * part of an expression, this code detects the start and end of text ranges
 * within JSX children. In order to properly count the number of children, we
 * distinguish jsxText from jsxEmptyText, which is a text range that simplifies
 * to the empty string after JSX whitespace trimming.
 *
 * It turns out that a JSX text range will simplify to the empty string if and
 * only if both of these conditions hold:
 * - The range consists entirely of whitespace characters (only counting space,
 *   tab, \r, and \n).
 * - The range has at least one newline.
 * This can be proven by analyzing any implementation of whitespace trimming,
 * e.g. formatJSXTextLiteral in Sucrase or cleanJSXElementLiteralChild in Babel.
 */
function jsxReadToken() {
    let sawNewline = false;
    let sawNonWhitespace = false;
    while (true) {
        if (state.pos >= input.length) {
            unexpected("Unterminated JSX contents");
            return;
        }
        const ch = input.charCodeAt(state.pos);
        if (ch === charCodes.lessThan || ch === charCodes.leftCurlyBrace) {
            if (state.pos === state.start) {
                if (ch === charCodes.lessThan) {
                    state.pos++;
                    finishToken(TokenType.jsxTagStart);
                    return;
                }
                getTokenFromCode(ch);
                return;
            }
            if (sawNewline && !sawNonWhitespace) {
                finishToken(TokenType.jsxEmptyText);
            }
            else {
                finishToken(TokenType.jsxText);
            }
            return;
        }
        // This is part of JSX text.
        if (ch === charCodes.lineFeed) {
            sawNewline = true;
        }
        else if (ch !== charCodes.space && ch !== charCodes.carriageReturn && ch !== charCodes.tab) {
            sawNonWhitespace = true;
        }
        state.pos++;
    }
}
function jsxReadString(quote) {
    state.pos++;
    for (;;) {
        if (state.pos >= input.length) {
            unexpected("Unterminated string constant");
            return;
        }
        const ch = input.charCodeAt(state.pos);
        if (ch === quote) {
            state.pos++;
            break;
        }
        state.pos++;
    }
    finishToken(TokenType.string);
}
// Read a JSX identifier (valid tag or attribute name).
//
// Optimized version since JSX identifiers can't contain
// escape characters and so can be read as single slice.
// Also assumes that first character was already checked
// by isIdentifierStart in readToken.
function jsxReadWord() {
    let ch;
    do {
        if (state.pos > input.length) {
            unexpected("Unexpectedly reached the end of input.");
            return;
        }
        ch = input.charCodeAt(++state.pos);
    } while (IS_IDENTIFIER_CHAR[ch] || ch === charCodes.dash);
    finishToken(TokenType.jsxName);
}
// Parse next token as JSX identifier
function jsxParseIdentifier() {
    nextJSXTagToken();
}
// Parse namespaced identifier.
function jsxParseNamespacedName(identifierRole) {
    jsxParseIdentifier();
    if (!eat(TokenType.colon)) {
        // Plain identifier, so this is an access.
        state.tokens[state.tokens.length - 1].identifierRole = identifierRole;
        return;
    }
    // Process the second half of the namespaced name.
    jsxParseIdentifier();
}
// Parses element name in any form - namespaced, member
// or single identifier.
function jsxParseElementName() {
    const firstTokenIndex = state.tokens.length;
    jsxParseNamespacedName(IdentifierRole.Access);
    let hadDot = false;
    while (match(TokenType.dot)) {
        hadDot = true;
        nextJSXTagToken();
        jsxParseIdentifier();
    }
    // For tags like <div> with a lowercase letter and no dots, the name is
    // actually *not* an identifier access, since it's referring to a built-in
    // tag name. Remove the identifier role in this case so that it's not
    // accidentally transformed by the imports transform when preserving JSX.
    if (!hadDot) {
        const firstToken = state.tokens[firstTokenIndex];
        const firstChar = input.charCodeAt(firstToken.start);
        if (firstChar >= charCodes.lowercaseA && firstChar <= charCodes.lowercaseZ) {
            firstToken.identifierRole = null;
        }
    }
}
// Parses any type of JSX attribute value.
function jsxParseAttributeValue() {
    switch (state.type) {
        case TokenType.braceL:
            next();
            parseExpression();
            nextJSXTagToken();
            return;
        case TokenType.jsxTagStart:
            jsxParseElement();
            nextJSXTagToken();
            return;
        case TokenType.string:
            nextJSXTagToken();
            return;
        default:
            unexpected("JSX value should be either an expression or a quoted JSX text");
    }
}
// Parse JSX spread child, after already processing the {
// Does not parse the closing }
function jsxParseSpreadChild() {
    expect(TokenType.ellipsis);
    parseExpression();
}
// Parses JSX opening tag starting after "<".
// Returns true if the tag was self-closing.
// Does not parse the last token.
function jsxParseOpeningElement(initialTokenIndex) {
    if (match(TokenType.jsxTagEnd)) {
        // This is an open-fragment.
        return false;
    }
    jsxParseElementName();
    if (isTypeScriptEnabled) {
        tsTryParseJSXTypeArgument();
    }
    let hasSeenPropSpread = false;
    while (!match(TokenType.slash) && !match(TokenType.jsxTagEnd) && !state.error) {
        if (eat(TokenType.braceL)) {
            hasSeenPropSpread = true;
            expect(TokenType.ellipsis);
            parseMaybeAssign();
            // }
            nextJSXTagToken();
            continue;
        }
        if (hasSeenPropSpread &&
            state.end - state.start === 3 &&
            input.charCodeAt(state.start) === charCodes.lowercaseK &&
            input.charCodeAt(state.start + 1) === charCodes.lowercaseE &&
            input.charCodeAt(state.start + 2) === charCodes.lowercaseY) {
            state.tokens[initialTokenIndex].jsxRole = JSXRole.KeyAfterPropSpread;
        }
        jsxParseNamespacedName(IdentifierRole.ObjectKey);
        if (match(TokenType.eq)) {
            nextJSXTagToken();
            jsxParseAttributeValue();
        }
    }
    const isSelfClosing = match(TokenType.slash);
    if (isSelfClosing) {
        // /
        nextJSXTagToken();
    }
    return isSelfClosing;
}
// Parses JSX closing tag starting after "</".
// Does not parse the last token.
function jsxParseClosingElement() {
    if (match(TokenType.jsxTagEnd)) {
        // Fragment syntax, so we immediately have a tag end.
        return;
    }
    jsxParseElementName();
}
// Parses entire JSX element, including its opening tag
// (starting after "<"), attributes, contents and closing tag.
// Does not parse the last token.
function jsxParseElementAt() {
    const initialTokenIndex = state.tokens.length - 1;
    state.tokens[initialTokenIndex].jsxRole = JSXRole.NoChildren;
    let numExplicitChildren = 0;
    const isSelfClosing = jsxParseOpeningElement(initialTokenIndex);
    if (!isSelfClosing) {
        nextJSXExprToken();
        while (true) {
            switch (state.type) {
                case TokenType.jsxTagStart:
                    nextJSXTagToken();
                    if (match(TokenType.slash)) {
                        nextJSXTagToken();
                        jsxParseClosingElement();
                        // Key after prop spread takes precedence over number of children,
                        // since it means we switch to createElement, which doesn't care
                        // about number of children.
                        if (state.tokens[initialTokenIndex].jsxRole !== JSXRole.KeyAfterPropSpread) {
                            if (numExplicitChildren === 1) {
                                state.tokens[initialTokenIndex].jsxRole = JSXRole.OneChild;
                            }
                            else if (numExplicitChildren > 1) {
                                state.tokens[initialTokenIndex].jsxRole = JSXRole.StaticChildren;
                            }
                        }
                        return;
                    }
                    numExplicitChildren++;
                    jsxParseElementAt();
                    nextJSXExprToken();
                    break;
                case TokenType.jsxText:
                    numExplicitChildren++;
                    nextJSXExprToken();
                    break;
                case TokenType.jsxEmptyText:
                    nextJSXExprToken();
                    break;
                case TokenType.braceL:
                    next();
                    if (match(TokenType.ellipsis)) {
                        jsxParseSpreadChild();
                        nextJSXExprToken();
                        // Spread children are a mechanism to explicitly mark children as
                        // static, so count it as 2 children to satisfy the "more than one
                        // child" condition.
                        numExplicitChildren += 2;
                    }
                    else {
                        // If we see {}, this is an empty pseudo-expression that doesn't
                        // count as a child.
                        if (!match(TokenType.braceR)) {
                            numExplicitChildren++;
                            parseExpression();
                        }
                        nextJSXExprToken();
                    }
                    break;
                // istanbul ignore next - should never happen
                default:
                    unexpected();
                    return;
            }
        }
    }
}
// Parses entire JSX element from current position.
// Does not parse the last token.
function jsxParseElement() {
    nextJSXTagToken();
    jsxParseElementAt();
}
// ==================================
// Overrides
// ==================================
function nextJSXTagToken() {
    state.tokens.push(new Token());
    skipSpace();
    state.start = state.pos;
    const code = input.charCodeAt(state.pos);
    if (IS_IDENTIFIER_START[code]) {
        jsxReadWord();
    }
    else if (code === charCodes.quotationMark || code === charCodes.apostrophe) {
        jsxReadString(code);
    }
    else {
        // The following tokens are just one character each.
        ++state.pos;
        switch (code) {
            case charCodes.greaterThan:
                finishToken(TokenType.jsxTagEnd);
                break;
            case charCodes.lessThan:
                finishToken(TokenType.jsxTagStart);
                break;
            case charCodes.slash:
                finishToken(TokenType.slash);
                break;
            case charCodes.equalsTo:
                finishToken(TokenType.eq);
                break;
            case charCodes.leftCurlyBrace:
                finishToken(TokenType.braceL);
                break;
            case charCodes.dot:
                finishToken(TokenType.dot);
                break;
            case charCodes.colon:
                finishToken(TokenType.colon);
                break;
            default:
                unexpected();
        }
    }
}
function nextJSXExprToken() {
    state.tokens.push(new Token());
    state.start = state.pos;
    jsxReadToken();
}

/**
 * Common parser code for TypeScript and Flow.
 */
// An apparent conditional expression could actually be an optional parameter in an arrow function.
function typedParseConditional(noIn) {
    // If we see ?:, this can't possibly be a valid conditional. typedParseParenItem will be called
    // later to finish off the arrow parameter. We also need to handle bare ? tokens for optional
    // parameters without type annotations, i.e. ?, and ?) .
    if (match(TokenType.question)) {
        const nextType = lookaheadType();
        if (nextType === TokenType.colon || nextType === TokenType.comma || nextType === TokenType.parenR) {
            return;
        }
    }
    baseParseConditional(noIn);
}
// Note: These "type casts" are *not* valid TS expressions.
// But we parse them here and change them when completing the arrow function.
function typedParseParenItem() {
    eatTypeToken(TokenType.question);
    if (match(TokenType.colon)) {
        if (isTypeScriptEnabled) {
            tsParseTypeAnnotation();
        }
        else if (isFlowEnabled) {
            flowParseTypeAnnotation();
        }
    }
}

/* eslint max-len: 0 */
// A recursive descent parser operates by defining functions for all
// syntactic elements, and recursively calling those, each function
// advancing the input stream and returning an AST node. Precedence
// of constructs (for example, the fact that `!x[1]` means `!(x[1])`
// instead of `(!x)[1]` is handled by the fact that the parser
// function that parses unary prefix operators is called first, and
// in turn calls the function that parses `[]` subscripts — that
// way, it'll receive the node for `x[1]` already parsed, and wraps
// *that* in the unary operator node.
//
// Acorn uses an [operator precedence parser][opp] to handle binary
// operator precedence, because it is much more compact than using
// the technique outlined above, which uses different, nesting
// functions to specify precedence, for all of the ten binary
// precedence levels that JavaScript defines.
//
// [opp]: http://en.wikipedia.org/wiki/Operator-precedence_parser
class StopState {
    stop;
    constructor(stop) {
        this.stop = stop;
    }
}
// ### Expression parsing
// These nest, from the most general expression type at the top to
// 'atomic', nondivisible expression types at the bottom. Most of
// the functions will simply let the function (s) below them parse,
// and, *if* the syntactic construct they handle is present, wrap
// the AST node that the inner parser gave them in another node.
function parseExpression(noIn = false) {
    parseMaybeAssign(noIn);
    if (match(TokenType.comma)) {
        while (eat(TokenType.comma)) {
            parseMaybeAssign(noIn);
        }
    }
}
/**
 * noIn is used when parsing a for loop so that we don't interpret a following "in" as the binary
 * operatior.
 * isWithinParens is used to indicate that we're parsing something that might be a comma expression
 * or might be an arrow function or might be a Flow type assertion (which requires explicit parens).
 * In these cases, we should allow : and ?: after the initial "left" part.
 */
function parseMaybeAssign(noIn = false, isWithinParens = false) {
    if (isTypeScriptEnabled) {
        return tsParseMaybeAssign(noIn, isWithinParens);
    }
    else if (isFlowEnabled) {
        return flowParseMaybeAssign(noIn, isWithinParens);
    }
    else {
        return baseParseMaybeAssign(noIn, isWithinParens);
    }
}
// Parse an assignment expression. This includes applications of
// operators like `+=`.
// Returns true if the expression was an arrow function.
function baseParseMaybeAssign(noIn, isWithinParens) {
    if (match(TokenType._yield)) {
        parseYield();
        return false;
    }
    if (match(TokenType.parenL) || match(TokenType.name) || match(TokenType._yield)) {
        state.potentialArrowAt = state.start;
    }
    const wasArrow = parseMaybeConditional(noIn);
    if (isWithinParens) {
        parseParenItem();
    }
    if (state.type & TokenType.IS_ASSIGN) {
        next();
        parseMaybeAssign(noIn);
        return false;
    }
    return wasArrow;
}
// Parse a ternary conditional (`?:`) operator.
// Returns true if the expression was an arrow function.
function parseMaybeConditional(noIn) {
    const wasArrow = parseExprOps(noIn);
    if (wasArrow) {
        return true;
    }
    parseConditional(noIn);
    return false;
}
function parseConditional(noIn) {
    if (isTypeScriptEnabled || isFlowEnabled) {
        typedParseConditional(noIn);
    }
    else {
        baseParseConditional(noIn);
    }
}
function baseParseConditional(noIn) {
    if (eat(TokenType.question)) {
        parseMaybeAssign();
        expect(TokenType.colon);
        parseMaybeAssign(noIn);
    }
}
// Start the precedence parser.
// Returns true if this was an arrow function
function parseExprOps(noIn) {
    const startTokenIndex = state.tokens.length;
    const wasArrow = parseMaybeUnary();
    if (wasArrow) {
        return true;
    }
    parseExprOp(startTokenIndex, -1, noIn);
    return false;
}
// Parse binary operators with the operator precedence parsing
// algorithm. `left` is the left-hand side of the operator.
// `minPrec` provides context that allows the function to stop and
// defer further parser to one of its callers when it encounters an
// operator that has a lower precedence than the set it is parsing.
function parseExprOp(startTokenIndex, minPrec, noIn) {
    if (isTypeScriptEnabled &&
        (TokenType._in & TokenType.PRECEDENCE_MASK) > minPrec &&
        !hasPrecedingLineBreak() &&
        (eatContextual(ContextualKeyword._as) || eatContextual(ContextualKeyword._satisfies))) {
        const oldIsType = pushTypeContext(1);
        tsParseType();
        popTypeContext(oldIsType);
        rescan_gt();
        parseExprOp(startTokenIndex, minPrec, noIn);
        return;
    }
    const prec = state.type & TokenType.PRECEDENCE_MASK;
    if (prec > 0 && (!noIn || !match(TokenType._in))) {
        if (prec > minPrec) {
            const op = state.type;
            next();
            if (op === TokenType.nullishCoalescing) {
                state.tokens[state.tokens.length - 1].nullishStartIndex = startTokenIndex;
            }
            const rhsStartTokenIndex = state.tokens.length;
            parseMaybeUnary();
            // Extend the right operand of this operator if possible.
            parseExprOp(rhsStartTokenIndex, op & TokenType.IS_RIGHT_ASSOCIATIVE ? prec - 1 : prec, noIn);
            if (op === TokenType.nullishCoalescing) {
                state.tokens[startTokenIndex].numNullishCoalesceStarts++;
                state.tokens[state.tokens.length - 1].numNullishCoalesceEnds++;
            }
            // Continue with any future operator holding this expression as the left operand.
            parseExprOp(startTokenIndex, minPrec, noIn);
        }
    }
}
// Parse unary operators, both prefix and postfix.
// Returns true if this was an arrow function.
function parseMaybeUnary() {
    if (isTypeScriptEnabled && !isJSXEnabled && eat(TokenType.lessThan)) {
        tsParseTypeAssertion();
        return false;
    }
    if (isContextual(ContextualKeyword._module) &&
        lookaheadCharCode() === charCodes.leftCurlyBrace &&
        !hasFollowingLineBreak()) {
        parseModuleExpression();
        return false;
    }
    if (state.type & TokenType.IS_PREFIX) {
        next();
        parseMaybeUnary();
        return false;
    }
    const wasArrow = parseExprSubscripts();
    if (wasArrow) {
        return true;
    }
    while (state.type & TokenType.IS_POSTFIX && !canInsertSemicolon()) {
        // The tokenizer calls everything a preincrement, so make it a postincrement when
        // we see it in that context.
        if (state.type === TokenType.preIncDec) {
            state.type = TokenType.postIncDec;
        }
        next();
    }
    return false;
}
// Parse call, dot, and `[]`-subscript expressions.
// Returns true if this was an arrow function.
function parseExprSubscripts() {
    const startTokenIndex = state.tokens.length;
    const wasArrow = parseExprAtom();
    if (wasArrow) {
        return true;
    }
    parseSubscripts(startTokenIndex);
    // If there was any optional chain operation, the start token would be marked
    // as such, so also mark the end now.
    if (state.tokens.length > startTokenIndex && state.tokens[startTokenIndex].isOptionalChainStart) {
        state.tokens[state.tokens.length - 1].isOptionalChainEnd = true;
    }
    return false;
}
function parseSubscripts(startTokenIndex, noCalls = false) {
    if (isFlowEnabled) {
        flowParseSubscripts(startTokenIndex, noCalls);
    }
    else {
        baseParseSubscripts(startTokenIndex, noCalls);
    }
}
function baseParseSubscripts(startTokenIndex, noCalls = false) {
    const stopState = new StopState(false);
    do {
        parseSubscript(startTokenIndex, noCalls, stopState);
    } while (!stopState.stop && !state.error);
}
function parseSubscript(startTokenIndex, noCalls, stopState) {
    if (isTypeScriptEnabled) {
        tsParseSubscript(startTokenIndex, noCalls, stopState);
    }
    else if (isFlowEnabled) {
        flowParseSubscript(startTokenIndex, noCalls, stopState);
    }
    else {
        baseParseSubscript(startTokenIndex, noCalls, stopState);
    }
}
/** Set 'state.stop = true' to indicate that we should stop parsing subscripts. */
function baseParseSubscript(startTokenIndex, noCalls, stopState) {
    if (!noCalls && eat(TokenType.doubleColon)) {
        parseNoCallExpr();
        stopState.stop = true;
        // Propagate startTokenIndex so that `a::b?.()` will keep `a` as the first token. We may want
        // to revisit this in the future when fully supporting bind syntax.
        parseSubscripts(startTokenIndex, noCalls);
    }
    else if (match(TokenType.questionDot)) {
        state.tokens[startTokenIndex].isOptionalChainStart = true;
        if (noCalls && lookaheadType() === TokenType.parenL) {
            stopState.stop = true;
            return;
        }
        next();
        state.tokens[state.tokens.length - 1].subscriptStartIndex = startTokenIndex;
        if (eat(TokenType.bracketL)) {
            parseExpression();
            expect(TokenType.bracketR);
        }
        else if (eat(TokenType.parenL)) {
            parseCallExpressionArguments();
        }
        else {
            parseMaybePrivateName();
        }
    }
    else if (eat(TokenType.dot)) {
        state.tokens[state.tokens.length - 1].subscriptStartIndex = startTokenIndex;
        parseMaybePrivateName();
    }
    else if (eat(TokenType.bracketL)) {
        state.tokens[state.tokens.length - 1].subscriptStartIndex = startTokenIndex;
        parseExpression();
        expect(TokenType.bracketR);
    }
    else if (!noCalls && match(TokenType.parenL)) {
        if (atPossibleAsync()) {
            // We see "async", but it's possible it's a usage of the name "async". Parse as if it's a
            // function call, and if we see an arrow later, backtrack and re-parse as a parameter list.
            const snapshot = state.snapshot();
            const asyncStartTokenIndex = state.tokens.length;
            next();
            state.tokens[state.tokens.length - 1].subscriptStartIndex = startTokenIndex;
            const callContextId = getNextContextId();
            state.tokens[state.tokens.length - 1].contextId = callContextId;
            parseCallExpressionArguments();
            state.tokens[state.tokens.length - 1].contextId = callContextId;
            if (shouldParseAsyncArrow()) {
                // We hit an arrow, so backtrack and start again parsing function parameters.
                state.restoreFromSnapshot(snapshot);
                stopState.stop = true;
                state.scopeDepth++;
                parseFunctionParams();
                parseAsyncArrowFromCallExpression(asyncStartTokenIndex);
            }
        }
        else {
            next();
            state.tokens[state.tokens.length - 1].subscriptStartIndex = startTokenIndex;
            const callContextId = getNextContextId();
            state.tokens[state.tokens.length - 1].contextId = callContextId;
            parseCallExpressionArguments();
            state.tokens[state.tokens.length - 1].contextId = callContextId;
        }
    }
    else if (match(TokenType.backQuote)) {
        // Tagged template expression.
        parseTemplate();
    }
    else {
        stopState.stop = true;
    }
}
function atPossibleAsync() {
    // This was made less strict than the original version to avoid passing around nodes, but it
    // should be safe to have rare false positives here.
    return (state.tokens[state.tokens.length - 1].contextualKeyword === ContextualKeyword._async &&
        !canInsertSemicolon());
}
function parseCallExpressionArguments() {
    let first = true;
    while (!eat(TokenType.parenR) && !state.error) {
        if (first) {
            first = false;
        }
        else {
            expect(TokenType.comma);
            if (eat(TokenType.parenR)) {
                break;
            }
        }
        parseExprListItem(false);
    }
}
function shouldParseAsyncArrow() {
    return match(TokenType.colon) || match(TokenType.arrow);
}
function parseAsyncArrowFromCallExpression(startTokenIndex) {
    if (isTypeScriptEnabled) {
        tsStartParseAsyncArrowFromCallExpression();
    }
    else if (isFlowEnabled) {
        flowStartParseAsyncArrowFromCallExpression();
    }
    expect(TokenType.arrow);
    parseArrowExpression(startTokenIndex);
}
// Parse a no-call expression (like argument of `new` or `::` operators).
function parseNoCallExpr() {
    const startTokenIndex = state.tokens.length;
    parseExprAtom();
    parseSubscripts(startTokenIndex, true);
}
// Parse an atomic expression — either a single token that is an
// expression, an expression started by a keyword like `function` or
// `new`, or an expression wrapped in punctuation like `()`, `[]`,
// or `{}`.
// Returns true if the parsed expression was an arrow function.
function parseExprAtom() {
    if (eat(TokenType.modulo)) {
        // V8 intrinsic expression. Just parse the identifier, and the function invocation is parsed
        // naturally.
        parseIdentifier();
        return false;
    }
    if (match(TokenType.jsxText) || match(TokenType.jsxEmptyText)) {
        parseLiteral();
        return false;
    }
    else if (match(TokenType.lessThan) && isJSXEnabled) {
        state.type = TokenType.jsxTagStart;
        jsxParseElement();
        next();
        return false;
    }
    const canBeArrow = state.potentialArrowAt === state.start;
    switch (state.type) {
        case TokenType.slash:
        case TokenType.assign:
            retokenizeSlashAsRegex();
        // Fall through.
        case TokenType._super:
        case TokenType._this:
        case TokenType.regexp:
        case TokenType.num:
        case TokenType.bigint:
        case TokenType.decimal:
        case TokenType.string:
        case TokenType._null:
        case TokenType._true:
        case TokenType._false:
            next();
            return false;
        case TokenType._import:
            next();
            if (match(TokenType.dot)) {
                // import.meta
                state.tokens[state.tokens.length - 1].type = TokenType.name;
                next();
                parseIdentifier();
            }
            return false;
        case TokenType.name: {
            const startTokenIndex = state.tokens.length;
            const functionStart = state.start;
            const contextualKeyword = state.contextualKeyword;
            parseIdentifier();
            if (contextualKeyword === ContextualKeyword._await) {
                parseAwait();
                return false;
            }
            else if (contextualKeyword === ContextualKeyword._async &&
                match(TokenType._function) &&
                !canInsertSemicolon()) {
                next();
                parseFunction(functionStart, false);
                return false;
            }
            else if (canBeArrow &&
                contextualKeyword === ContextualKeyword._async &&
                !canInsertSemicolon() &&
                match(TokenType.name)) {
                state.scopeDepth++;
                parseBindingIdentifier(false);
                expect(TokenType.arrow);
                // let foo = async bar => {};
                parseArrowExpression(startTokenIndex);
                return true;
            }
            else if (match(TokenType._do) && !canInsertSemicolon()) {
                next();
                parseBlock();
                return false;
            }
            if (canBeArrow && !canInsertSemicolon() && match(TokenType.arrow)) {
                state.scopeDepth++;
                markPriorBindingIdentifier(false);
                expect(TokenType.arrow);
                parseArrowExpression(startTokenIndex);
                return true;
            }
            state.tokens[state.tokens.length - 1].identifierRole = IdentifierRole.Access;
            return false;
        }
        case TokenType._do: {
            next();
            parseBlock();
            return false;
        }
        case TokenType.parenL: {
            const wasArrow = parseParenAndDistinguishExpression(canBeArrow);
            return wasArrow;
        }
        case TokenType.bracketL:
            next();
            parseExprList(TokenType.bracketR, true);
            return false;
        case TokenType.braceL:
            parseObj(false, false);
            return false;
        case TokenType._function:
            parseFunctionExpression();
            return false;
        case TokenType.at:
            parseDecorators();
        // Fall through.
        case TokenType._class:
            parseClass(false);
            return false;
        case TokenType._new:
            parseNew();
            return false;
        case TokenType.backQuote:
            parseTemplate();
            return false;
        case TokenType.doubleColon: {
            next();
            parseNoCallExpr();
            return false;
        }
        case TokenType.hash: {
            const code = lookaheadCharCode();
            if (IS_IDENTIFIER_START[code] || code === charCodes.backslash) {
                parseMaybePrivateName();
            }
            else {
                next();
            }
            // Smart pipeline topic reference.
            return false;
        }
        default:
            unexpected();
            return false;
    }
}
function parseMaybePrivateName() {
    eat(TokenType.hash);
    parseIdentifier();
}
function parseFunctionExpression() {
    const functionStart = state.start;
    parseIdentifier();
    if (eat(TokenType.dot)) {
        // function.sent
        parseIdentifier();
    }
    parseFunction(functionStart, false);
}
function parseLiteral() {
    next();
}
function parseParenExpression() {
    expect(TokenType.parenL);
    parseExpression();
    expect(TokenType.parenR);
}
// Returns true if this was an arrow expression.
function parseParenAndDistinguishExpression(canBeArrow) {
    // Assume this is a normal parenthesized expression, but if we see an arrow, we'll bail and
    // start over as a parameter list.
    const snapshot = state.snapshot();
    const startTokenIndex = state.tokens.length;
    expect(TokenType.parenL);
    let first = true;
    while (!match(TokenType.parenR) && !state.error) {
        if (first) {
            first = false;
        }
        else {
            expect(TokenType.comma);
            if (match(TokenType.parenR)) {
                break;
            }
        }
        if (match(TokenType.ellipsis)) {
            parseRest(false /* isBlockScope */);
            parseParenItem();
            break;
        }
        else {
            parseMaybeAssign(false, true);
        }
    }
    expect(TokenType.parenR);
    if (canBeArrow && shouldParseArrow()) {
        const wasArrow = parseArrow();
        if (wasArrow) {
            // It was an arrow function this whole time, so start over and parse it as params so that we
            // get proper token annotations.
            state.restoreFromSnapshot(snapshot);
            state.scopeDepth++;
            // Don't specify a context ID because arrow functions don't need a context ID.
            parseFunctionParams();
            parseArrow();
            parseArrowExpression(startTokenIndex);
            if (state.error) {
                // Nevermind! This must have been something that looks very much like an
                // arrow function but where its "parameter list" isn't actually a valid
                // parameter list. Force non-arrow parsing.
                // See https://github.com/alangpierce/sucrase/issues/666 for an example.
                state.restoreFromSnapshot(snapshot);
                parseParenAndDistinguishExpression(false);
                return false;
            }
            return true;
        }
    }
    return false;
}
function shouldParseArrow() {
    return match(TokenType.colon) || !canInsertSemicolon();
}
// Returns whether there was an arrow token.
function parseArrow() {
    if (isTypeScriptEnabled) {
        return tsParseArrow();
    }
    else if (isFlowEnabled) {
        return flowParseArrow();
    }
    else {
        return eat(TokenType.arrow);
    }
}
function parseParenItem() {
    if (isTypeScriptEnabled || isFlowEnabled) {
        typedParseParenItem();
    }
}
// New's precedence is slightly tricky. It must allow its argument to
// be a `[]` or dot subscript expression, but not a call — at least,
// not without wrapping it in parentheses. Thus, it uses the noCalls
// argument to parseSubscripts to prevent it from consuming the
// argument list.
function parseNew() {
    expect(TokenType._new);
    if (eat(TokenType.dot)) {
        // new.target
        parseIdentifier();
        return;
    }
    parseNewCallee();
    if (isFlowEnabled) {
        flowStartParseNewArguments();
    }
    if (eat(TokenType.parenL)) {
        parseExprList(TokenType.parenR);
    }
}
function parseNewCallee() {
    parseNoCallExpr();
    eat(TokenType.questionDot);
}
function parseTemplate() {
    // Finish `, read quasi
    nextTemplateToken();
    // Finish quasi, read ${
    nextTemplateToken();
    while (!match(TokenType.backQuote) && !state.error) {
        expect(TokenType.dollarBraceL);
        parseExpression();
        // Finish }, read quasi
        nextTemplateToken();
        // Finish quasi, read either ${ or `
        nextTemplateToken();
    }
    next();
}
// Parse an object literal or binding pattern.
function parseObj(isPattern, isBlockScope) {
    // Attach a context ID to the object open and close brace and each object key.
    const contextId = getNextContextId();
    let first = true;
    next();
    state.tokens[state.tokens.length - 1].contextId = contextId;
    while (!eat(TokenType.braceR) && !state.error) {
        if (first) {
            first = false;
        }
        else {
            expect(TokenType.comma);
            if (eat(TokenType.braceR)) {
                break;
            }
        }
        let isGenerator = false;
        if (match(TokenType.ellipsis)) {
            const previousIndex = state.tokens.length;
            parseSpread();
            if (isPattern) {
                // Mark role when the only thing being spread over is an identifier.
                if (state.tokens.length === previousIndex + 2) {
                    markPriorBindingIdentifier(isBlockScope);
                }
                if (eat(TokenType.braceR)) {
                    break;
                }
            }
            continue;
        }
        if (!isPattern) {
            isGenerator = eat(TokenType.star);
        }
        if (!isPattern && isContextual(ContextualKeyword._async)) {
            if (isGenerator)
                unexpected();
            parseIdentifier();
            if (match(TokenType.colon) ||
                match(TokenType.parenL) ||
                match(TokenType.braceR) ||
                match(TokenType.eq) ||
                match(TokenType.comma)) ;
            else {
                if (match(TokenType.star)) {
                    next();
                    isGenerator = true;
                }
                parsePropertyName(contextId);
            }
        }
        else {
            parsePropertyName(contextId);
        }
        parseObjPropValue(isPattern, isBlockScope, contextId);
    }
    state.tokens[state.tokens.length - 1].contextId = contextId;
}
function isGetterOrSetterMethod(isPattern) {
    // We go off of the next and don't bother checking if the node key is actually "get" or "set".
    // This lets us avoid generating a node, and should only make the validation worse.
    return (!isPattern &&
        (match(TokenType.string) || // get "string"() {}
            match(TokenType.num) || // get 1() {}
            match(TokenType.bracketL) || // get ["string"]() {}
            match(TokenType.name) || // get foo() {}
            !!(state.type & TokenType.IS_KEYWORD)) // get debugger() {}
    );
}
// Returns true if this was a method.
function parseObjectMethod(isPattern, objectContextId) {
    // We don't need to worry about modifiers because object methods can't have optional bodies, so
    // the start will never be used.
    const functionStart = state.start;
    if (match(TokenType.parenL)) {
        if (isPattern)
            unexpected();
        parseMethod(functionStart, /* isConstructor */ false);
        return true;
    }
    if (isGetterOrSetterMethod(isPattern)) {
        parsePropertyName(objectContextId);
        parseMethod(functionStart, /* isConstructor */ false);
        return true;
    }
    return false;
}
function parseObjectProperty(isPattern, isBlockScope) {
    if (eat(TokenType.colon)) {
        if (isPattern) {
            parseMaybeDefault(isBlockScope);
        }
        else {
            parseMaybeAssign(false);
        }
        return;
    }
    // Since there's no colon, we assume this is an object shorthand.
    // If we're in a destructuring, we've now discovered that the key was actually an assignee, so
    // we need to tag it as a declaration with the appropriate scope. Otherwise, we might need to
    // transform it on access, so mark it as a normal object shorthand.
    let identifierRole;
    if (isPattern) {
        if (state.scopeDepth === 0) {
            identifierRole = IdentifierRole.ObjectShorthandTopLevelDeclaration;
        }
        else if (isBlockScope) {
            identifierRole = IdentifierRole.ObjectShorthandBlockScopedDeclaration;
        }
        else {
            identifierRole = IdentifierRole.ObjectShorthandFunctionScopedDeclaration;
        }
    }
    else {
        identifierRole = IdentifierRole.ObjectShorthand;
    }
    state.tokens[state.tokens.length - 1].identifierRole = identifierRole;
    // Regardless of whether we know this to be a pattern or if we're in an ambiguous context, allow
    // parsing as if there's a default value.
    parseMaybeDefault(isBlockScope, true);
}
function parseObjPropValue(isPattern, isBlockScope, objectContextId) {
    if (isTypeScriptEnabled) {
        tsStartParseObjPropValue();
    }
    else if (isFlowEnabled) {
        flowStartParseObjPropValue();
    }
    const wasMethod = parseObjectMethod(isPattern, objectContextId);
    if (!wasMethod) {
        parseObjectProperty(isPattern, isBlockScope);
    }
}
function parsePropertyName(objectContextId) {
    if (isFlowEnabled) {
        flowParseVariance();
    }
    if (eat(TokenType.bracketL)) {
        state.tokens[state.tokens.length - 1].contextId = objectContextId;
        parseMaybeAssign();
        expect(TokenType.bracketR);
        state.tokens[state.tokens.length - 1].contextId = objectContextId;
    }
    else {
        if (match(TokenType.num) || match(TokenType.string) || match(TokenType.bigint) || match(TokenType.decimal)) {
            parseExprAtom();
        }
        else {
            parseMaybePrivateName();
        }
        state.tokens[state.tokens.length - 1].identifierRole = IdentifierRole.ObjectKey;
        state.tokens[state.tokens.length - 1].contextId = objectContextId;
    }
}
// Parse object or class method.
function parseMethod(functionStart, isConstructor) {
    const funcContextId = getNextContextId();
    state.scopeDepth++;
    const startTokenIndex = state.tokens.length;
    const allowModifiers = isConstructor; // For TypeScript parameter properties
    parseFunctionParams(allowModifiers, funcContextId);
    parseFunctionBodyAndFinish(functionStart, funcContextId);
    const endTokenIndex = state.tokens.length;
    state.scopes.push(new Scope(startTokenIndex, endTokenIndex, true));
    state.scopeDepth--;
}
// Parse arrow function expression.
// If the parameters are provided, they will be converted to an
// assignable list.
function parseArrowExpression(startTokenIndex) {
    parseFunctionBody(true);
    const endTokenIndex = state.tokens.length;
    state.scopes.push(new Scope(startTokenIndex, endTokenIndex, true));
    state.scopeDepth--;
}
function parseFunctionBodyAndFinish(functionStart, funcContextId = 0) {
    if (isTypeScriptEnabled) {
        tsParseFunctionBodyAndFinish(functionStart, funcContextId);
    }
    else if (isFlowEnabled) {
        flowParseFunctionBodyAndFinish(funcContextId);
    }
    else {
        parseFunctionBody(false, funcContextId);
    }
}
function parseFunctionBody(allowExpression, funcContextId = 0) {
    const isExpression = allowExpression && !match(TokenType.braceL);
    if (isExpression) {
        parseMaybeAssign();
    }
    else {
        parseBlock(true /* isFunctionScope */, funcContextId);
    }
}
// Parses a comma-separated list of expressions, and returns them as
// an array. `close` is the token type that ends the list, and
// `allowEmpty` can be turned on to allow subsequent commas with
// nothing in between them to be parsed as `null` (which is needed
// for array literals).
function parseExprList(close, allowEmpty = false) {
    let first = true;
    while (!eat(close) && !state.error) {
        if (first) {
            first = false;
        }
        else {
            expect(TokenType.comma);
            if (eat(close))
                break;
        }
        parseExprListItem(allowEmpty);
    }
}
function parseExprListItem(allowEmpty) {
    if (allowEmpty && match(TokenType.comma)) ;
    else if (match(TokenType.ellipsis)) {
        parseSpread();
        parseParenItem();
    }
    else if (match(TokenType.question)) {
        // Partial function application proposal.
        next();
    }
    else {
        parseMaybeAssign(false, true);
    }
}
// Parse the next token as an identifier.
function parseIdentifier() {
    next();
    state.tokens[state.tokens.length - 1].type = TokenType.name;
}
// Parses await expression inside async function.
function parseAwait() {
    parseMaybeUnary();
}
// Parses yield expression inside generator.
function parseYield() {
    next();
    if (!match(TokenType.semi) && !canInsertSemicolon()) {
        eat(TokenType.star);
        parseMaybeAssign();
    }
}
// https://github.com/tc39/proposal-js-module-blocks
function parseModuleExpression() {
    expectContextual(ContextualKeyword._module);
    expect(TokenType.braceL);
    // For now, just call parseBlockBody to parse the block. In the future when we
    // implement full support, we'll want to emit scopes and possibly other
    // information.
    parseBlockBody(TokenType.braceR);
}

/* eslint max-len: 0 */
function isMaybeDefaultImport(lookahead) {
    return ((lookahead.type === TokenType.name || !!(lookahead.type & TokenType.IS_KEYWORD)) &&
        lookahead.contextualKeyword !== ContextualKeyword._from);
}
function flowParseTypeInitialiser(tok) {
    const oldIsType = pushTypeContext(0);
    expect(tok || TokenType.colon);
    flowParseType();
    popTypeContext(oldIsType);
}
function flowParsePredicate() {
    expect(TokenType.modulo);
    expectContextual(ContextualKeyword._checks);
    if (eat(TokenType.parenL)) {
        parseExpression();
        expect(TokenType.parenR);
    }
}
function flowParseTypeAndPredicateInitialiser() {
    const oldIsType = pushTypeContext(0);
    expect(TokenType.colon);
    if (match(TokenType.modulo)) {
        flowParsePredicate();
    }
    else {
        flowParseType();
        if (match(TokenType.modulo)) {
            flowParsePredicate();
        }
    }
    popTypeContext(oldIsType);
}
function flowParseDeclareClass() {
    next();
    flowParseInterfaceish(/* isClass */ true);
}
function flowParseDeclareFunction() {
    next();
    parseIdentifier();
    if (match(TokenType.lessThan)) {
        flowParseTypeParameterDeclaration();
    }
    expect(TokenType.parenL);
    flowParseFunctionTypeParams();
    expect(TokenType.parenR);
    flowParseTypeAndPredicateInitialiser();
    semicolon();
}
function flowParseDeclare() {
    if (match(TokenType._class)) {
        flowParseDeclareClass();
    }
    else if (match(TokenType._function)) {
        flowParseDeclareFunction();
    }
    else if (match(TokenType._var)) {
        flowParseDeclareVariable();
    }
    else if (eatContextual(ContextualKeyword._module)) {
        if (eat(TokenType.dot)) {
            flowParseDeclareModuleExports();
        }
        else {
            flowParseDeclareModule();
        }
    }
    else if (isContextual(ContextualKeyword._type)) {
        flowParseDeclareTypeAlias();
    }
    else if (isContextual(ContextualKeyword._opaque)) {
        flowParseDeclareOpaqueType();
    }
    else if (isContextual(ContextualKeyword._interface)) {
        flowParseDeclareInterface();
    }
    else if (match(TokenType._export)) {
        flowParseDeclareExportDeclaration();
    }
    else {
        unexpected();
    }
}
function flowParseDeclareVariable() {
    next();
    flowParseTypeAnnotatableIdentifier();
    semicolon();
}
function flowParseDeclareModule() {
    if (match(TokenType.string)) {
        parseExprAtom();
    }
    else {
        parseIdentifier();
    }
    expect(TokenType.braceL);
    while (!match(TokenType.braceR) && !state.error) {
        if (match(TokenType._import)) {
            next();
            parseImport();
        }
        else {
            unexpected();
        }
    }
    expect(TokenType.braceR);
}
function flowParseDeclareExportDeclaration() {
    expect(TokenType._export);
    if (eat(TokenType._default)) {
        if (match(TokenType._function) || match(TokenType._class)) {
            // declare export default class ...
            // declare export default function ...
            flowParseDeclare();
        }
        else {
            // declare export default [type];
            flowParseType();
            semicolon();
        }
    }
    else if (match(TokenType._var) || // declare export var ...
        match(TokenType._function) || // declare export function ...
        match(TokenType._class) || // declare export class ...
        isContextual(ContextualKeyword._opaque) // declare export opaque ..
    ) {
        flowParseDeclare();
    }
    else if (match(TokenType.star) || // declare export * from ''
        match(TokenType.braceL) || // declare export {} ...
        isContextual(ContextualKeyword._interface) || // declare export interface ...
        isContextual(ContextualKeyword._type) || // declare export type ...
        isContextual(ContextualKeyword._opaque) // declare export opaque type ...
    ) {
        parseExport();
    }
    else {
        unexpected();
    }
}
function flowParseDeclareModuleExports() {
    expectContextual(ContextualKeyword._exports);
    flowParseTypeAnnotation();
    semicolon();
}
function flowParseDeclareTypeAlias() {
    next();
    flowParseTypeAlias();
}
function flowParseDeclareOpaqueType() {
    next();
    flowParseOpaqueType(true);
}
function flowParseDeclareInterface() {
    next();
    flowParseInterfaceish();
}
// Interfaces
function flowParseInterfaceish(isClass = false) {
    flowParseRestrictedIdentifier();
    if (match(TokenType.lessThan)) {
        flowParseTypeParameterDeclaration();
    }
    if (eat(TokenType._extends)) {
        do {
            flowParseInterfaceExtends();
        } while (!isClass && eat(TokenType.comma));
    }
    if (isContextual(ContextualKeyword._mixins)) {
        next();
        do {
            flowParseInterfaceExtends();
        } while (eat(TokenType.comma));
    }
    if (isContextual(ContextualKeyword._implements)) {
        next();
        do {
            flowParseInterfaceExtends();
        } while (eat(TokenType.comma));
    }
    flowParseObjectType(isClass, false, isClass);
}
function flowParseInterfaceExtends() {
    flowParseQualifiedTypeIdentifier(false);
    if (match(TokenType.lessThan)) {
        flowParseTypeParameterInstantiation();
    }
}
function flowParseInterface() {
    flowParseInterfaceish();
}
function flowParseRestrictedIdentifier() {
    parseIdentifier();
}
function flowParseTypeAlias() {
    flowParseRestrictedIdentifier();
    if (match(TokenType.lessThan)) {
        flowParseTypeParameterDeclaration();
    }
    flowParseTypeInitialiser(TokenType.eq);
    semicolon();
}
function flowParseOpaqueType(declare) {
    expectContextual(ContextualKeyword._type);
    flowParseRestrictedIdentifier();
    if (match(TokenType.lessThan)) {
        flowParseTypeParameterDeclaration();
    }
    // Parse the supertype
    if (match(TokenType.colon)) {
        flowParseTypeInitialiser(TokenType.colon);
    }
    if (!declare) {
        flowParseTypeInitialiser(TokenType.eq);
    }
    semicolon();
}
function flowParseTypeParameter() {
    flowParseVariance();
    flowParseTypeAnnotatableIdentifier();
    if (eat(TokenType.eq)) {
        flowParseType();
    }
}
function flowParseTypeParameterDeclaration() {
    const oldIsType = pushTypeContext(0);
    // istanbul ignore else: this condition is already checked at all call sites
    if (match(TokenType.lessThan) || match(TokenType.typeParameterStart)) {
        next();
    }
    else {
        unexpected();
    }
    do {
        flowParseTypeParameter();
        if (!match(TokenType.greaterThan)) {
            expect(TokenType.comma);
        }
    } while (!match(TokenType.greaterThan) && !state.error);
    expect(TokenType.greaterThan);
    popTypeContext(oldIsType);
}
function flowParseTypeParameterInstantiation() {
    const oldIsType = pushTypeContext(0);
    expect(TokenType.lessThan);
    while (!match(TokenType.greaterThan) && !state.error) {
        flowParseType();
        if (!match(TokenType.greaterThan)) {
            expect(TokenType.comma);
        }
    }
    expect(TokenType.greaterThan);
    popTypeContext(oldIsType);
}
function flowParseInterfaceType() {
    expectContextual(ContextualKeyword._interface);
    if (eat(TokenType._extends)) {
        do {
            flowParseInterfaceExtends();
        } while (eat(TokenType.comma));
    }
    flowParseObjectType(false, false, false);
}
function flowParseObjectPropertyKey() {
    if (match(TokenType.num) || match(TokenType.string)) {
        parseExprAtom();
    }
    else {
        parseIdentifier();
    }
}
function flowParseObjectTypeIndexer() {
    // Note: bracketL has already been consumed
    if (lookaheadType() === TokenType.colon) {
        flowParseObjectPropertyKey();
        flowParseTypeInitialiser();
    }
    else {
        flowParseType();
    }
    expect(TokenType.bracketR);
    flowParseTypeInitialiser();
}
function flowParseObjectTypeInternalSlot() {
    // Note: both bracketL have already been consumed
    flowParseObjectPropertyKey();
    expect(TokenType.bracketR);
    expect(TokenType.bracketR);
    if (match(TokenType.lessThan) || match(TokenType.parenL)) {
        flowParseObjectTypeMethodish();
    }
    else {
        eat(TokenType.question);
        flowParseTypeInitialiser();
    }
}
function flowParseObjectTypeMethodish() {
    if (match(TokenType.lessThan)) {
        flowParseTypeParameterDeclaration();
    }
    expect(TokenType.parenL);
    while (!match(TokenType.parenR) && !match(TokenType.ellipsis) && !state.error) {
        flowParseFunctionTypeParam();
        if (!match(TokenType.parenR)) {
            expect(TokenType.comma);
        }
    }
    if (eat(TokenType.ellipsis)) {
        flowParseFunctionTypeParam();
    }
    expect(TokenType.parenR);
    flowParseTypeInitialiser();
}
function flowParseObjectTypeCallProperty() {
    flowParseObjectTypeMethodish();
}
function flowParseObjectType(allowStatic, allowExact, allowProto) {
    let endDelim;
    if (allowExact && match(TokenType.braceBarL)) {
        expect(TokenType.braceBarL);
        endDelim = TokenType.braceBarR;
    }
    else {
        expect(TokenType.braceL);
        endDelim = TokenType.braceR;
    }
    while (!match(endDelim) && !state.error) {
        if (allowProto && isContextual(ContextualKeyword._proto)) {
            const lookahead = lookaheadType();
            if (lookahead !== TokenType.colon && lookahead !== TokenType.question) {
                next();
                allowStatic = false;
            }
        }
        if (allowStatic && isContextual(ContextualKeyword._static)) {
            const lookahead = lookaheadType();
            if (lookahead !== TokenType.colon && lookahead !== TokenType.question) {
                next();
            }
        }
        flowParseVariance();
        if (eat(TokenType.bracketL)) {
            if (eat(TokenType.bracketL)) {
                flowParseObjectTypeInternalSlot();
            }
            else {
                flowParseObjectTypeIndexer();
            }
        }
        else if (match(TokenType.parenL) || match(TokenType.lessThan)) {
            flowParseObjectTypeCallProperty();
        }
        else {
            if (isContextual(ContextualKeyword._get) || isContextual(ContextualKeyword._set)) {
                const lookahead = lookaheadType();
                if (lookahead === TokenType.name || lookahead === TokenType.string || lookahead === TokenType.num) {
                    next();
                }
            }
            flowParseObjectTypeProperty();
        }
        flowObjectTypeSemicolon();
    }
    expect(endDelim);
}
function flowParseObjectTypeProperty() {
    if (match(TokenType.ellipsis)) {
        expect(TokenType.ellipsis);
        if (!eat(TokenType.comma)) {
            eat(TokenType.semi);
        }
        // Explicit inexact object syntax.
        if (match(TokenType.braceR)) {
            return;
        }
        flowParseType();
    }
    else {
        flowParseObjectPropertyKey();
        if (match(TokenType.lessThan) || match(TokenType.parenL)) {
            // This is a method property
            flowParseObjectTypeMethodish();
        }
        else {
            eat(TokenType.question);
            flowParseTypeInitialiser();
        }
    }
}
function flowObjectTypeSemicolon() {
    if (!eat(TokenType.semi) && !eat(TokenType.comma) && !match(TokenType.braceR) && !match(TokenType.braceBarR)) {
        unexpected();
    }
}
function flowParseQualifiedTypeIdentifier(initialIdAlreadyParsed) {
    if (!initialIdAlreadyParsed) {
        parseIdentifier();
    }
    while (eat(TokenType.dot)) {
        parseIdentifier();
    }
}
function flowParseGenericType() {
    flowParseQualifiedTypeIdentifier(true);
    if (match(TokenType.lessThan)) {
        flowParseTypeParameterInstantiation();
    }
}
function flowParseTypeofType() {
    expect(TokenType._typeof);
    flowParsePrimaryType();
}
function flowParseTupleType() {
    expect(TokenType.bracketL);
    // We allow trailing commas
    while (state.pos < input.length && !match(TokenType.bracketR)) {
        flowParseType();
        if (match(TokenType.bracketR)) {
            break;
        }
        expect(TokenType.comma);
    }
    expect(TokenType.bracketR);
}
function flowParseFunctionTypeParam() {
    const lookahead = lookaheadType();
    if (lookahead === TokenType.colon || lookahead === TokenType.question) {
        parseIdentifier();
        eat(TokenType.question);
        flowParseTypeInitialiser();
    }
    else {
        flowParseType();
    }
}
function flowParseFunctionTypeParams() {
    while (!match(TokenType.parenR) && !match(TokenType.ellipsis) && !state.error) {
        flowParseFunctionTypeParam();
        if (!match(TokenType.parenR)) {
            expect(TokenType.comma);
        }
    }
    if (eat(TokenType.ellipsis)) {
        flowParseFunctionTypeParam();
    }
}
// The parsing of types roughly parallels the parsing of expressions, and
// primary types are kind of like primary expressions...they're the
// primitives with which other types are constructed.
function flowParsePrimaryType() {
    let isGroupedType = false;
    const oldNoAnonFunctionType = state.noAnonFunctionType;
    switch (state.type) {
        case TokenType.name: {
            if (isContextual(ContextualKeyword._interface)) {
                flowParseInterfaceType();
                return;
            }
            parseIdentifier();
            flowParseGenericType();
            return;
        }
        case TokenType.braceL:
            flowParseObjectType(false, false, false);
            return;
        case TokenType.braceBarL:
            flowParseObjectType(false, true, false);
            return;
        case TokenType.bracketL:
            flowParseTupleType();
            return;
        case TokenType.lessThan:
            flowParseTypeParameterDeclaration();
            expect(TokenType.parenL);
            flowParseFunctionTypeParams();
            expect(TokenType.parenR);
            expect(TokenType.arrow);
            flowParseType();
            return;
        case TokenType.parenL:
            next();
            // Check to see if this is actually a grouped type
            if (!match(TokenType.parenR) && !match(TokenType.ellipsis)) {
                if (match(TokenType.name)) {
                    const token = lookaheadType();
                    isGroupedType = token !== TokenType.question && token !== TokenType.colon;
                }
                else {
                    isGroupedType = true;
                }
            }
            if (isGroupedType) {
                state.noAnonFunctionType = false;
                flowParseType();
                state.noAnonFunctionType = oldNoAnonFunctionType;
                // A `,` or a `) =>` means this is an anonymous function type
                if (state.noAnonFunctionType ||
                    !(match(TokenType.comma) || (match(TokenType.parenR) && lookaheadType() === TokenType.arrow))) {
                    expect(TokenType.parenR);
                    return;
                }
                else {
                    // Eat a comma if there is one
                    eat(TokenType.comma);
                }
            }
            flowParseFunctionTypeParams();
            expect(TokenType.parenR);
            expect(TokenType.arrow);
            flowParseType();
            return;
        case TokenType.minus:
            next();
            parseLiteral();
            return;
        case TokenType.string:
        case TokenType.num:
        case TokenType._true:
        case TokenType._false:
        case TokenType._null:
        case TokenType._this:
        case TokenType._void:
        case TokenType.star:
            next();
            return;
        default:
            if (state.type === TokenType._typeof) {
                flowParseTypeofType();
                return;
            }
            else if (state.type & TokenType.IS_KEYWORD) {
                next();
                state.tokens[state.tokens.length - 1].type = TokenType.name;
                return;
            }
    }
    unexpected();
}
function flowParsePostfixType() {
    flowParsePrimaryType();
    while (!canInsertSemicolon() && (match(TokenType.bracketL) || match(TokenType.questionDot))) {
        eat(TokenType.questionDot);
        expect(TokenType.bracketL);
        if (eat(TokenType.bracketR)) ;
        else {
            // Indexed access type
            flowParseType();
            expect(TokenType.bracketR);
        }
    }
}
function flowParsePrefixType() {
    if (eat(TokenType.question)) {
        flowParsePrefixType();
    }
    else {
        flowParsePostfixType();
    }
}
function flowParseAnonFunctionWithoutParens() {
    flowParsePrefixType();
    if (!state.noAnonFunctionType && eat(TokenType.arrow)) {
        flowParseType();
    }
}
function flowParseIntersectionType() {
    eat(TokenType.bitwiseAND);
    flowParseAnonFunctionWithoutParens();
    while (eat(TokenType.bitwiseAND)) {
        flowParseAnonFunctionWithoutParens();
    }
}
function flowParseUnionType() {
    eat(TokenType.bitwiseOR);
    flowParseIntersectionType();
    while (eat(TokenType.bitwiseOR)) {
        flowParseIntersectionType();
    }
}
function flowParseType() {
    flowParseUnionType();
}
function flowParseTypeAnnotation() {
    flowParseTypeInitialiser();
}
function flowParseTypeAnnotatableIdentifier() {
    parseIdentifier();
    if (match(TokenType.colon)) {
        flowParseTypeAnnotation();
    }
}
function flowParseVariance() {
    if (match(TokenType.plus) || match(TokenType.minus)) {
        next();
        state.tokens[state.tokens.length - 1].isType = true;
    }
}
// ==================================
// Overrides
// ==================================
function flowParseFunctionBodyAndFinish(funcContextId) {
    // For arrow functions, `parseArrow` handles the return type itself.
    if (match(TokenType.colon)) {
        flowParseTypeAndPredicateInitialiser();
    }
    parseFunctionBody(false, funcContextId);
}
function flowParseSubscript(startTokenIndex, noCalls, stopState) {
    if (match(TokenType.questionDot) && lookaheadType() === TokenType.lessThan) {
        if (noCalls) {
            stopState.stop = true;
            return;
        }
        next();
        flowParseTypeParameterInstantiation();
        expect(TokenType.parenL);
        parseCallExpressionArguments();
        return;
    }
    else if (!noCalls && match(TokenType.lessThan)) {
        const snapshot = state.snapshot();
        flowParseTypeParameterInstantiation();
        expect(TokenType.parenL);
        parseCallExpressionArguments();
        if (state.error) {
            state.restoreFromSnapshot(snapshot);
        }
        else {
            return;
        }
    }
    baseParseSubscript(startTokenIndex, noCalls, stopState);
}
function flowStartParseNewArguments() {
    if (match(TokenType.lessThan)) {
        const snapshot = state.snapshot();
        flowParseTypeParameterInstantiation();
        if (state.error) {
            state.restoreFromSnapshot(snapshot);
        }
    }
}
// interfaces
function flowTryParseStatement() {
    if (match(TokenType.name) && state.contextualKeyword === ContextualKeyword._interface) {
        const oldIsType = pushTypeContext(0);
        next();
        flowParseInterface();
        popTypeContext(oldIsType);
        return true;
    }
    else if (isContextual(ContextualKeyword._enum)) {
        flowParseEnumDeclaration();
        return true;
    }
    return false;
}
function flowTryParseExportDefaultExpression() {
    if (isContextual(ContextualKeyword._enum)) {
        flowParseEnumDeclaration();
        return true;
    }
    return false;
}
// declares, interfaces and type aliases
function flowParseIdentifierStatement(contextualKeyword) {
    if (contextualKeyword === ContextualKeyword._declare) {
        if (match(TokenType._class) ||
            match(TokenType.name) ||
            match(TokenType._function) ||
            match(TokenType._var) ||
            match(TokenType._export)) {
            const oldIsType = pushTypeContext(1);
            flowParseDeclare();
            popTypeContext(oldIsType);
        }
    }
    else if (match(TokenType.name)) {
        if (contextualKeyword === ContextualKeyword._interface) {
            const oldIsType = pushTypeContext(1);
            flowParseInterface();
            popTypeContext(oldIsType);
        }
        else if (contextualKeyword === ContextualKeyword._type) {
            const oldIsType = pushTypeContext(1);
            flowParseTypeAlias();
            popTypeContext(oldIsType);
        }
        else if (contextualKeyword === ContextualKeyword._opaque) {
            const oldIsType = pushTypeContext(1);
            flowParseOpaqueType(false);
            popTypeContext(oldIsType);
        }
    }
    semicolon();
}
// export type
function flowShouldParseExportDeclaration() {
    return (isContextual(ContextualKeyword._type) ||
        isContextual(ContextualKeyword._interface) ||
        isContextual(ContextualKeyword._opaque) ||
        isContextual(ContextualKeyword._enum));
}
function flowShouldDisallowExportDefaultSpecifier() {
    return (match(TokenType.name) &&
        (state.contextualKeyword === ContextualKeyword._type ||
            state.contextualKeyword === ContextualKeyword._interface ||
            state.contextualKeyword === ContextualKeyword._opaque ||
            state.contextualKeyword === ContextualKeyword._enum));
}
function flowParseExportDeclaration() {
    if (isContextual(ContextualKeyword._type)) {
        const oldIsType = pushTypeContext(1);
        next();
        if (match(TokenType.braceL)) {
            // export type { foo, bar };
            parseExportSpecifiers();
            parseExportFrom();
        }
        else {
            // export type Foo = Bar;
            flowParseTypeAlias();
        }
        popTypeContext(oldIsType);
    }
    else if (isContextual(ContextualKeyword._opaque)) {
        const oldIsType = pushTypeContext(1);
        next();
        // export opaque type Foo = Bar;
        flowParseOpaqueType(false);
        popTypeContext(oldIsType);
    }
    else if (isContextual(ContextualKeyword._interface)) {
        const oldIsType = pushTypeContext(1);
        next();
        flowParseInterface();
        popTypeContext(oldIsType);
    }
    else {
        parseStatement(true);
    }
}
function flowShouldParseExportStar() {
    return match(TokenType.star) || (isContextual(ContextualKeyword._type) && lookaheadType() === TokenType.star);
}
function flowParseExportStar() {
    if (eatContextual(ContextualKeyword._type)) {
        const oldIsType = pushTypeContext(2);
        baseParseExportStar();
        popTypeContext(oldIsType);
    }
    else {
        baseParseExportStar();
    }
}
// parse a the super class type parameters and implements
function flowAfterParseClassSuper(hasSuper) {
    if (hasSuper && match(TokenType.lessThan)) {
        flowParseTypeParameterInstantiation();
    }
    if (isContextual(ContextualKeyword._implements)) {
        const oldIsType = pushTypeContext(0);
        next();
        state.tokens[state.tokens.length - 1].type = TokenType._implements;
        do {
            flowParseRestrictedIdentifier();
            if (match(TokenType.lessThan)) {
                flowParseTypeParameterInstantiation();
            }
        } while (eat(TokenType.comma));
        popTypeContext(oldIsType);
    }
}
// parse type parameters for object method shorthand
function flowStartParseObjPropValue() {
    // method shorthand
    if (match(TokenType.lessThan)) {
        flowParseTypeParameterDeclaration();
        if (!match(TokenType.parenL))
            unexpected();
    }
}
function flowParseAssignableListItemTypes() {
    const oldIsType = pushTypeContext(0);
    eat(TokenType.question);
    if (match(TokenType.colon)) {
        flowParseTypeAnnotation();
    }
    popTypeContext(oldIsType);
}
// parse typeof and type imports
function flowStartParseImportSpecifiers() {
    if (match(TokenType._typeof) || isContextual(ContextualKeyword._type)) {
        const lh = lookaheadTypeAndKeyword();
        if (isMaybeDefaultImport(lh) || lh.type === TokenType.braceL || lh.type === TokenType.star) {
            next();
        }
    }
}
// parse import-type/typeof shorthand
function flowParseImportSpecifier() {
    const isTypeKeyword = state.contextualKeyword === ContextualKeyword._type || state.type === TokenType._typeof;
    if (isTypeKeyword) {
        next();
    }
    else {
        parseIdentifier();
    }
    if (isContextual(ContextualKeyword._as) && !isLookaheadContextual(ContextualKeyword._as)) {
        parseIdentifier();
        if (isTypeKeyword && !match(TokenType.name) && !(state.type & TokenType.IS_KEYWORD)) ;
        else {
            // `import {type as foo`
            parseIdentifier();
        }
    }
    else {
        if (isTypeKeyword && (match(TokenType.name) || !!(state.type & TokenType.IS_KEYWORD))) {
            // `import {type foo`
            parseIdentifier();
        }
        if (eatContextual(ContextualKeyword._as)) {
            parseIdentifier();
        }
    }
}
// parse function type parameters - function foo<T>() {}
function flowStartParseFunctionParams() {
    // Originally this checked if the method is a getter/setter, but if it was, we'd crash soon
    // anyway, so don't try to propagate that information.
    if (match(TokenType.lessThan)) {
        const oldIsType = pushTypeContext(0);
        flowParseTypeParameterDeclaration();
        popTypeContext(oldIsType);
    }
}
// parse flow type annotations on variable declarator heads - let foo: string = bar
function flowAfterParseVarHead() {
    if (match(TokenType.colon)) {
        flowParseTypeAnnotation();
    }
}
// parse the return type of an async arrow function - let foo = (async (): number => {});
function flowStartParseAsyncArrowFromCallExpression() {
    if (match(TokenType.colon)) {
        const oldNoAnonFunctionType = state.noAnonFunctionType;
        state.noAnonFunctionType = true;
        flowParseTypeAnnotation();
        state.noAnonFunctionType = oldNoAnonFunctionType;
    }
}
// We need to support type parameter declarations for arrow functions. This
// is tricky. There are three situations we need to handle
//
// 1. This is either JSX or an arrow function. We'll try JSX first. If that
//    fails, we'll try an arrow function. If that fails, we'll throw the JSX
//    error.
// 2. This is an arrow function. We'll parse the type parameter declaration,
//    parse the rest, make sure the rest is an arrow function, and go from
//    there
// 3. This is neither. Just call the super method
function flowParseMaybeAssign(noIn, isWithinParens) {
    if (match(TokenType.lessThan)) {
        const snapshot = state.snapshot();
        let wasArrow = baseParseMaybeAssign(noIn, isWithinParens);
        if (state.error) {
            state.restoreFromSnapshot(snapshot);
            state.type = TokenType.typeParameterStart;
        }
        else {
            return wasArrow;
        }
        const oldIsType = pushTypeContext(0);
        flowParseTypeParameterDeclaration();
        popTypeContext(oldIsType);
        wasArrow = baseParseMaybeAssign(noIn, isWithinParens);
        if (wasArrow) {
            return true;
        }
        unexpected();
    }
    return baseParseMaybeAssign(noIn, isWithinParens);
}
// handle return types for arrow functions
function flowParseArrow() {
    if (match(TokenType.colon)) {
        const oldIsType = pushTypeContext(0);
        const snapshot = state.snapshot();
        const oldNoAnonFunctionType = state.noAnonFunctionType;
        state.noAnonFunctionType = true;
        flowParseTypeAndPredicateInitialiser();
        state.noAnonFunctionType = oldNoAnonFunctionType;
        if (canInsertSemicolon())
            unexpected();
        if (!match(TokenType.arrow))
            unexpected();
        if (state.error) {
            state.restoreFromSnapshot(snapshot);
        }
        popTypeContext(oldIsType);
    }
    return eat(TokenType.arrow);
}
function flowParseSubscripts(startTokenIndex, noCalls = false) {
    if (state.tokens[state.tokens.length - 1].contextualKeyword === ContextualKeyword._async &&
        match(TokenType.lessThan)) {
        const snapshot = state.snapshot();
        const wasArrow = parseAsyncArrowWithTypeParameters();
        if (wasArrow && !state.error) {
            return;
        }
        state.restoreFromSnapshot(snapshot);
    }
    baseParseSubscripts(startTokenIndex, noCalls);
}
// Returns true if there was an arrow function here.
function parseAsyncArrowWithTypeParameters() {
    state.scopeDepth++;
    const startTokenIndex = state.tokens.length;
    parseFunctionParams();
    if (!parseArrow()) {
        return false;
    }
    parseArrowExpression(startTokenIndex);
    return true;
}
function flowParseEnumDeclaration() {
    expectContextual(ContextualKeyword._enum);
    state.tokens[state.tokens.length - 1].type = TokenType._enum;
    parseIdentifier();
    flowParseEnumBody();
}
function flowParseEnumBody() {
    if (eatContextual(ContextualKeyword._of)) {
        next();
    }
    expect(TokenType.braceL);
    flowParseEnumMembers();
    expect(TokenType.braceR);
}
function flowParseEnumMembers() {
    while (!match(TokenType.braceR) && !state.error) {
        if (eat(TokenType.ellipsis)) {
            break;
        }
        flowParseEnumMember();
        if (!match(TokenType.braceR)) {
            expect(TokenType.comma);
        }
    }
}
function flowParseEnumMember() {
    parseIdentifier();
    if (eat(TokenType.eq)) {
        // Flow enum values are always just one token (a string, number, or boolean literal).
        next();
    }
}

/* eslint max-len: 0 */
function parseTopLevel() {
    parseBlockBody(TokenType.eof);
    state.scopes.push(new Scope(0, state.tokens.length, true));
    if (state.scopeDepth !== 0) {
        throw new Error(`Invalid scope depth at end of file: ${state.scopeDepth}`);
    }
    return new File(state.tokens, state.scopes);
}
// Parse a single statement.
//
// If expecting a statement and finding a slash operator, parse a
// regular expression literal. This is to handle cases like
// `if (foo) /blah/.exec(foo)`, where looking at the previous token
// does not help.
function parseStatement(declaration) {
    if (isFlowEnabled) {
        if (flowTryParseStatement()) {
            return;
        }
    }
    if (match(TokenType.at)) {
        parseDecorators();
    }
    parseStatementContent(declaration);
}
function parseStatementContent(declaration) {
    if (isTypeScriptEnabled) {
        if (tsTryParseStatementContent()) {
            return;
        }
    }
    const starttype = state.type;
    // Most types of statements are recognized by the keyword they
    // start with. Many are trivial to parse, some require a bit of
    // complexity.
    switch (starttype) {
        case TokenType._break:
        case TokenType._continue:
            parseBreakContinueStatement();
            return;
        case TokenType._debugger:
            parseDebuggerStatement();
            return;
        case TokenType._do:
            parseDoStatement();
            return;
        case TokenType._for:
            parseForStatement();
            return;
        case TokenType._function:
            if (lookaheadType() === TokenType.dot)
                break;
            if (!declaration)
                unexpected();
            parseFunctionStatement();
            return;
        case TokenType._class:
            if (!declaration)
                unexpected();
            parseClass(true);
            return;
        case TokenType._if:
            parseIfStatement();
            return;
        case TokenType._return:
            parseReturnStatement();
            return;
        case TokenType._switch:
            parseSwitchStatement();
            return;
        case TokenType._throw:
            parseThrowStatement();
            return;
        case TokenType._try:
            parseTryStatement();
            return;
        case TokenType._let:
        case TokenType._const:
            if (!declaration)
                unexpected(); // NOTE: falls through to _var
        case TokenType._var:
            parseVarStatement(starttype !== TokenType._var);
            return;
        case TokenType._while:
            parseWhileStatement();
            return;
        case TokenType.braceL:
            parseBlock();
            return;
        case TokenType.semi:
            parseEmptyStatement();
            return;
        case TokenType._export:
        case TokenType._import: {
            const nextType = lookaheadType();
            if (nextType === TokenType.parenL || nextType === TokenType.dot) {
                break;
            }
            next();
            if (starttype === TokenType._import) {
                parseImport();
            }
            else {
                parseExport();
            }
            return;
        }
        case TokenType.name:
            if (state.contextualKeyword === ContextualKeyword._async) {
                const functionStart = state.start;
                // peek ahead and see if next token is a function
                const snapshot = state.snapshot();
                next();
                if (match(TokenType._function) && !canInsertSemicolon()) {
                    expect(TokenType._function);
                    parseFunction(functionStart, true);
                    return;
                }
                else {
                    state.restoreFromSnapshot(snapshot);
                }
            }
            else if (state.contextualKeyword === ContextualKeyword._using &&
                !hasFollowingLineBreak() &&
                // Statements like `using[0]` and `using in foo` aren't actual using
                // declarations.
                lookaheadType() === TokenType.name) {
                parseVarStatement(true);
                return;
            }
            else if (startsAwaitUsing()) {
                expectContextual(ContextualKeyword._await);
                parseVarStatement(true);
                return;
            }
    }
    // If the statement does not start with a statement keyword or a
    // brace, it's an ExpressionStatement or LabeledStatement. We
    // simply start parsing an expression, and afterwards, if the
    // next token is a colon and the expression was a simple
    // Identifier node, we switch to interpreting it as a label.
    const initialTokensLength = state.tokens.length;
    parseExpression();
    let simpleName = null;
    if (state.tokens.length === initialTokensLength + 1) {
        const token = state.tokens[state.tokens.length - 1];
        if (token.type === TokenType.name) {
            simpleName = token.contextualKeyword;
        }
    }
    if (simpleName == null) {
        semicolon();
        return;
    }
    if (eat(TokenType.colon)) {
        parseLabeledStatement();
    }
    else {
        // This was an identifier, so we might want to handle flow/typescript-specific cases.
        parseIdentifierStatement(simpleName);
    }
}
/**
 * Determine if we're positioned at an `await using` declaration.
 *
 * Note that this can happen either in place of a regular variable declaration
 * or in a loop body, and in both places, there are similar-looking cases where
 * we need to return false.
 *
 * Examples returning true:
 * await using foo = bar();
 * for (await using a of b) {}
 *
 * Examples returning false:
 * await using
 * await using + 1
 * await using instanceof T
 * for (await using;;) {}
 *
 * For now, we early return if we don't see `await`, then do a simple
 * backtracking-based lookahead for the `using` and identifier tokens. In the
 * future, this could be optimized with a character-based approach.
 */
function startsAwaitUsing() {
    if (!isContextual(ContextualKeyword._await)) {
        return false;
    }
    const snapshot = state.snapshot();
    // await
    next();
    if (!isContextual(ContextualKeyword._using) || hasPrecedingLineBreak()) {
        state.restoreFromSnapshot(snapshot);
        return false;
    }
    // using
    next();
    if (!match(TokenType.name) || hasPrecedingLineBreak()) {
        state.restoreFromSnapshot(snapshot);
        return false;
    }
    state.restoreFromSnapshot(snapshot);
    return true;
}
function parseDecorators() {
    while (match(TokenType.at)) {
        parseDecorator();
    }
}
function parseDecorator() {
    next();
    if (eat(TokenType.parenL)) {
        parseExpression();
        expect(TokenType.parenR);
    }
    else {
        parseIdentifier();
        while (eat(TokenType.dot)) {
            parseIdentifier();
        }
        parseMaybeDecoratorArguments();
    }
}
function parseMaybeDecoratorArguments() {
    if (isTypeScriptEnabled) {
        tsParseMaybeDecoratorArguments();
    }
    else {
        baseParseMaybeDecoratorArguments();
    }
}
function baseParseMaybeDecoratorArguments() {
    if (eat(TokenType.parenL)) {
        parseCallExpressionArguments();
    }
}
function parseBreakContinueStatement() {
    next();
    if (!isLineTerminator()) {
        parseIdentifier();
        semicolon();
    }
}
function parseDebuggerStatement() {
    next();
    semicolon();
}
function parseDoStatement() {
    next();
    parseStatement(false);
    expect(TokenType._while);
    parseParenExpression();
    eat(TokenType.semi);
}
function parseForStatement() {
    state.scopeDepth++;
    const startTokenIndex = state.tokens.length;
    parseAmbiguousForStatement();
    const endTokenIndex = state.tokens.length;
    state.scopes.push(new Scope(startTokenIndex, endTokenIndex, false));
    state.scopeDepth--;
}
/**
 * Determine if this token is a `using` declaration (explicit resource
 * management) as part of a loop.
 * https://github.com/tc39/proposal-explicit-resource-management
 */
function isUsingInLoop() {
    if (!isContextual(ContextualKeyword._using)) {
        return false;
    }
    // This must be `for (using of`, where `using` is the name of the loop
    // variable.
    if (isLookaheadContextual(ContextualKeyword._of)) {
        return false;
    }
    return true;
}
// Disambiguating between a `for` and a `for`/`in` or `for`/`of`
// loop is non-trivial. Basically, we have to parse the init `var`
// statement or expression, disallowing the `in` operator (see
// the second parameter to `parseExpression`), and then check
// whether the next token is `in` or `of`. When there is no init
// part (semicolon immediately after the opening parenthesis), it
// is a regular `for` loop.
function parseAmbiguousForStatement() {
    next();
    let forAwait = false;
    if (isContextual(ContextualKeyword._await)) {
        forAwait = true;
        next();
    }
    expect(TokenType.parenL);
    if (match(TokenType.semi)) {
        if (forAwait) {
            unexpected();
        }
        parseFor();
        return;
    }
    const isAwaitUsing = startsAwaitUsing();
    if (isAwaitUsing || match(TokenType._var) || match(TokenType._let) || match(TokenType._const) || isUsingInLoop()) {
        if (isAwaitUsing) {
            expectContextual(ContextualKeyword._await);
        }
        next();
        parseVar(true, state.type !== TokenType._var);
        if (match(TokenType._in) || isContextual(ContextualKeyword._of)) {
            parseForIn(forAwait);
            return;
        }
        parseFor();
        return;
    }
    parseExpression(true);
    if (match(TokenType._in) || isContextual(ContextualKeyword._of)) {
        parseForIn(forAwait);
        return;
    }
    if (forAwait) {
        unexpected();
    }
    parseFor();
}
function parseFunctionStatement() {
    const functionStart = state.start;
    next();
    parseFunction(functionStart, true);
}
function parseIfStatement() {
    next();
    parseParenExpression();
    parseStatement(false);
    if (eat(TokenType._else)) {
        parseStatement(false);
    }
}
function parseReturnStatement() {
    next();
    // In `return` (and `break`/`continue`), the keywords with
    // optional arguments, we eagerly look for a semicolon or the
    // possibility to insert one.
    if (!isLineTerminator()) {
        parseExpression();
        semicolon();
    }
}
function parseSwitchStatement() {
    next();
    parseParenExpression();
    state.scopeDepth++;
    const startTokenIndex = state.tokens.length;
    expect(TokenType.braceL);
    // Don't bother validation; just go through any sequence of cases, defaults, and statements.
    while (!match(TokenType.braceR) && !state.error) {
        if (match(TokenType._case) || match(TokenType._default)) {
            const isCase = match(TokenType._case);
            next();
            if (isCase) {
                parseExpression();
            }
            expect(TokenType.colon);
        }
        else {
            parseStatement(true);
        }
    }
    next(); // Closing brace
    const endTokenIndex = state.tokens.length;
    state.scopes.push(new Scope(startTokenIndex, endTokenIndex, false));
    state.scopeDepth--;
}
function parseThrowStatement() {
    next();
    parseExpression();
    semicolon();
}
function parseCatchClauseParam() {
    parseBindingAtom(true /* isBlockScope */);
    if (isTypeScriptEnabled) {
        tsTryParseTypeAnnotation();
    }
}
function parseTryStatement() {
    next();
    parseBlock();
    if (match(TokenType._catch)) {
        next();
        let catchBindingStartTokenIndex = null;
        if (match(TokenType.parenL)) {
            state.scopeDepth++;
            catchBindingStartTokenIndex = state.tokens.length;
            expect(TokenType.parenL);
            parseCatchClauseParam();
            expect(TokenType.parenR);
        }
        parseBlock();
        if (catchBindingStartTokenIndex != null) {
            // We need a special scope for the catch binding which includes the binding itself and the
            // catch block.
            const endTokenIndex = state.tokens.length;
            state.scopes.push(new Scope(catchBindingStartTokenIndex, endTokenIndex, false));
            state.scopeDepth--;
        }
    }
    if (eat(TokenType._finally)) {
        parseBlock();
    }
}
function parseVarStatement(isBlockScope) {
    next();
    parseVar(false, isBlockScope);
    semicolon();
}
function parseWhileStatement() {
    next();
    parseParenExpression();
    parseStatement(false);
}
function parseEmptyStatement() {
    next();
}
function parseLabeledStatement() {
    parseStatement(true);
}
/**
 * Parse a statement starting with an identifier of the given name. Subclasses match on the name
 * to handle statements like "declare".
 */
function parseIdentifierStatement(contextualKeyword) {
    if (isTypeScriptEnabled) {
        tsParseIdentifierStatement(contextualKeyword);
    }
    else if (isFlowEnabled) {
        flowParseIdentifierStatement(contextualKeyword);
    }
    else {
        semicolon();
    }
}
// Parse a semicolon-enclosed block of statements.
function parseBlock(isFunctionScope = false, contextId = 0) {
    const startTokenIndex = state.tokens.length;
    state.scopeDepth++;
    expect(TokenType.braceL);
    if (contextId) {
        state.tokens[state.tokens.length - 1].contextId = contextId;
    }
    parseBlockBody(TokenType.braceR);
    if (contextId) {
        state.tokens[state.tokens.length - 1].contextId = contextId;
    }
    const endTokenIndex = state.tokens.length;
    state.scopes.push(new Scope(startTokenIndex, endTokenIndex, isFunctionScope));
    state.scopeDepth--;
}
function parseBlockBody(end) {
    while (!eat(end) && !state.error) {
        parseStatement(true);
    }
}
// Parse a regular `for` loop. The disambiguation code in
// `parseStatement` will already have parsed the init statement or
// expression.
function parseFor() {
    expect(TokenType.semi);
    if (!match(TokenType.semi)) {
        parseExpression();
    }
    expect(TokenType.semi);
    if (!match(TokenType.parenR)) {
        parseExpression();
    }
    expect(TokenType.parenR);
    parseStatement(false);
}
// Parse a `for`/`in` and `for`/`of` loop, which are almost
// same from parser's perspective.
function parseForIn(forAwait) {
    if (forAwait) {
        eatContextual(ContextualKeyword._of);
    }
    else {
        next();
    }
    parseExpression();
    expect(TokenType.parenR);
    parseStatement(false);
}
// Parse a list of variable declarations.
function parseVar(isFor, isBlockScope) {
    while (true) {
        parseVarHead(isBlockScope);
        if (eat(TokenType.eq)) {
            const eqIndex = state.tokens.length - 1;
            parseMaybeAssign(isFor);
            state.tokens[eqIndex].rhsEndIndex = state.tokens.length;
        }
        if (!eat(TokenType.comma)) {
            break;
        }
    }
}
function parseVarHead(isBlockScope) {
    parseBindingAtom(isBlockScope);
    if (isTypeScriptEnabled) {
        tsAfterParseVarHead();
    }
    else if (isFlowEnabled) {
        flowAfterParseVarHead();
    }
}
// Parse a function declaration or literal (depending on the
// `isStatement` parameter).
function parseFunction(functionStart, isStatement, optionalId = false) {
    if (match(TokenType.star)) {
        next();
    }
    if (isStatement && !optionalId && !match(TokenType.name) && !match(TokenType._yield)) {
        unexpected();
    }
    let nameScopeStartTokenIndex = null;
    if (match(TokenType.name)) {
        // Expression-style functions should limit their name's scope to the function body, so we make
        // a new function scope to enforce that.
        if (!isStatement) {
            nameScopeStartTokenIndex = state.tokens.length;
            state.scopeDepth++;
        }
        parseBindingIdentifier(false);
    }
    const startTokenIndex = state.tokens.length;
    state.scopeDepth++;
    parseFunctionParams();
    parseFunctionBodyAndFinish(functionStart);
    const endTokenIndex = state.tokens.length;
    // In addition to the block scope of the function body, we need a separate function-style scope
    // that includes the params.
    state.scopes.push(new Scope(startTokenIndex, endTokenIndex, true));
    state.scopeDepth--;
    if (nameScopeStartTokenIndex !== null) {
        state.scopes.push(new Scope(nameScopeStartTokenIndex, endTokenIndex, true));
        state.scopeDepth--;
    }
}
function parseFunctionParams(allowModifiers = false, funcContextId = 0) {
    if (isTypeScriptEnabled) {
        tsStartParseFunctionParams();
    }
    else if (isFlowEnabled) {
        flowStartParseFunctionParams();
    }
    expect(TokenType.parenL);
    if (funcContextId) {
        state.tokens[state.tokens.length - 1].contextId = funcContextId;
    }
    parseBindingList(TokenType.parenR, false /* isBlockScope */, false /* allowEmpty */, allowModifiers, funcContextId);
    if (funcContextId) {
        state.tokens[state.tokens.length - 1].contextId = funcContextId;
    }
}
// Parse a class declaration or literal (depending on the
// `isStatement` parameter).
function parseClass(isStatement, optionalId = false) {
    // Put a context ID on the class keyword, the open-brace, and the close-brace, so that later
    // code can easily navigate to meaningful points on the class.
    const contextId = getNextContextId();
    next();
    state.tokens[state.tokens.length - 1].contextId = contextId;
    state.tokens[state.tokens.length - 1].isExpression = !isStatement;
    // Like with functions, we declare a special "name scope" from the start of the name to the end
    // of the class, but only with expression-style classes, to represent the fact that the name is
    // available to the body of the class but not an outer declaration.
    let nameScopeStartTokenIndex = null;
    if (!isStatement) {
        nameScopeStartTokenIndex = state.tokens.length;
        state.scopeDepth++;
    }
    parseClassId(isStatement, optionalId);
    parseClassSuper();
    const openBraceIndex = state.tokens.length;
    parseClassBody(contextId);
    if (state.error) {
        return;
    }
    state.tokens[openBraceIndex].contextId = contextId;
    state.tokens[state.tokens.length - 1].contextId = contextId;
    if (nameScopeStartTokenIndex !== null) {
        const endTokenIndex = state.tokens.length;
        state.scopes.push(new Scope(nameScopeStartTokenIndex, endTokenIndex, false));
        state.scopeDepth--;
    }
}
function isClassProperty() {
    return match(TokenType.eq) || match(TokenType.semi) || match(TokenType.braceR) || match(TokenType.bang) || match(TokenType.colon);
}
function isClassMethod() {
    return match(TokenType.parenL) || match(TokenType.lessThan);
}
function parseClassBody(classContextId) {
    expect(TokenType.braceL);
    while (!eat(TokenType.braceR) && !state.error) {
        if (eat(TokenType.semi)) {
            continue;
        }
        if (match(TokenType.at)) {
            parseDecorator();
            continue;
        }
        const memberStart = state.start;
        parseClassMember(memberStart, classContextId);
    }
}
function parseClassMember(memberStart, classContextId) {
    if (isTypeScriptEnabled) {
        tsParseModifiers([
            ContextualKeyword._declare,
            ContextualKeyword._public,
            ContextualKeyword._protected,
            ContextualKeyword._private,
            ContextualKeyword._override,
        ]);
    }
    let isStatic = false;
    if (match(TokenType.name) && state.contextualKeyword === ContextualKeyword._static) {
        parseIdentifier(); // eats 'static'
        if (isClassMethod()) {
            parseClassMethod(memberStart, /* isConstructor */ false);
            return;
        }
        else if (isClassProperty()) {
            parseClassProperty();
            return;
        }
        // otherwise something static
        state.tokens[state.tokens.length - 1].type = TokenType._static;
        isStatic = true;
        if (match(TokenType.braceL)) {
            // This is a static block. Mark the word "static" with the class context ID for class element
            // detection and parse as a regular block.
            state.tokens[state.tokens.length - 1].contextId = classContextId;
            parseBlock();
            return;
        }
    }
    parseClassMemberWithIsStatic(memberStart, isStatic, classContextId);
}
function parseClassMemberWithIsStatic(memberStart, isStatic, classContextId) {
    if (isTypeScriptEnabled) {
        if (tsTryParseClassMemberWithIsStatic(isStatic)) {
            return;
        }
    }
    if (eat(TokenType.star)) {
        // a generator
        parseClassPropertyName(classContextId);
        parseClassMethod(memberStart, /* isConstructor */ false);
        return;
    }
    // Get the identifier name so we can tell if it's actually a keyword like "async", "get", or
    // "set".
    parseClassPropertyName(classContextId);
    let isConstructor = false;
    const token = state.tokens[state.tokens.length - 1];
    // We allow "constructor" as either an identifier or a string.
    if (token.contextualKeyword === ContextualKeyword._constructor) {
        isConstructor = true;
    }
    parsePostMemberNameModifiers();
    if (isClassMethod()) {
        parseClassMethod(memberStart, isConstructor);
    }
    else if (isClassProperty()) {
        parseClassProperty();
    }
    else if (token.contextualKeyword === ContextualKeyword._async && !isLineTerminator()) {
        state.tokens[state.tokens.length - 1].type = TokenType._async;
        // an async method
        const isGenerator = match(TokenType.star);
        if (isGenerator) {
            next();
        }
        // The so-called parsed name would have been "async": get the real name.
        parseClassPropertyName(classContextId);
        parsePostMemberNameModifiers();
        parseClassMethod(memberStart, false /* isConstructor */);
    }
    else if ((token.contextualKeyword === ContextualKeyword._get ||
        token.contextualKeyword === ContextualKeyword._set) &&
        !(isLineTerminator() && match(TokenType.star))) {
        if (token.contextualKeyword === ContextualKeyword._get) {
            state.tokens[state.tokens.length - 1].type = TokenType._get;
        }
        else {
            state.tokens[state.tokens.length - 1].type = TokenType._set;
        }
        // `get\n*` is an uninitialized property named 'get' followed by a generator.
        // a getter or setter
        // The so-called parsed name would have been "get/set": get the real name.
        parseClassPropertyName(classContextId);
        parseClassMethod(memberStart, /* isConstructor */ false);
    }
    else if (token.contextualKeyword === ContextualKeyword._accessor && !isLineTerminator()) {
        parseClassPropertyName(classContextId);
        parseClassProperty();
    }
    else if (isLineTerminator()) {
        // an uninitialized class property (due to ASI, since we don't otherwise recognize the next token)
        parseClassProperty();
    }
    else {
        unexpected();
    }
}
function parseClassMethod(functionStart, isConstructor) {
    if (isTypeScriptEnabled) {
        tsTryParseTypeParameters();
    }
    else if (isFlowEnabled) {
        if (match(TokenType.lessThan)) {
            flowParseTypeParameterDeclaration();
        }
    }
    parseMethod(functionStart, isConstructor);
}
// Return the name of the class property, if it is a simple identifier.
function parseClassPropertyName(classContextId) {
    parsePropertyName(classContextId);
}
function parsePostMemberNameModifiers() {
    if (isTypeScriptEnabled) {
        const oldIsType = pushTypeContext(0);
        eat(TokenType.question);
        popTypeContext(oldIsType);
    }
}
function parseClassProperty() {
    if (isTypeScriptEnabled) {
        eatTypeToken(TokenType.bang);
        tsTryParseTypeAnnotation();
    }
    else if (isFlowEnabled) {
        if (match(TokenType.colon)) {
            flowParseTypeAnnotation();
        }
    }
    if (match(TokenType.eq)) {
        const equalsTokenIndex = state.tokens.length;
        next();
        parseMaybeAssign();
        state.tokens[equalsTokenIndex].rhsEndIndex = state.tokens.length;
    }
    semicolon();
}
function parseClassId(isStatement, optionalId = false) {
    if (isTypeScriptEnabled &&
        (!isStatement || optionalId) &&
        isContextual(ContextualKeyword._implements)) {
        return;
    }
    if (match(TokenType.name)) {
        parseBindingIdentifier(true);
    }
    if (isTypeScriptEnabled) {
        tsTryParseTypeParameters();
    }
    else if (isFlowEnabled) {
        if (match(TokenType.lessThan)) {
            flowParseTypeParameterDeclaration();
        }
    }
}
// Returns true if there was a superclass.
function parseClassSuper() {
    let hasSuper = false;
    if (eat(TokenType._extends)) {
        parseExprSubscripts();
        hasSuper = true;
    }
    else {
        hasSuper = false;
    }
    if (isTypeScriptEnabled) {
        tsAfterParseClassSuper(hasSuper);
    }
    else if (isFlowEnabled) {
        flowAfterParseClassSuper(hasSuper);
    }
}
// Parses module export declaration.
function parseExport() {
    const exportIndex = state.tokens.length - 1;
    if (isTypeScriptEnabled) {
        if (tsTryParseExport()) {
            return;
        }
    }
    // export * from '...'
    if (shouldParseExportStar()) {
        parseExportStar();
    }
    else if (isExportDefaultSpecifier()) {
        // export default from
        parseIdentifier();
        if (match(TokenType.comma) && lookaheadType() === TokenType.star) {
            expect(TokenType.comma);
            expect(TokenType.star);
            expectContextual(ContextualKeyword._as);
            parseIdentifier();
        }
        else {
            parseExportSpecifiersMaybe();
        }
        parseExportFrom();
    }
    else if (eat(TokenType._default)) {
        // export default ...
        parseExportDefaultExpression();
    }
    else if (shouldParseExportDeclaration()) {
        parseExportDeclaration();
    }
    else {
        // export { x, y as z } [from '...']
        parseExportSpecifiers();
        parseExportFrom();
    }
    state.tokens[exportIndex].rhsEndIndex = state.tokens.length;
}
function parseExportDefaultExpression() {
    if (isTypeScriptEnabled) {
        if (tsTryParseExportDefaultExpression()) {
            return;
        }
    }
    if (isFlowEnabled) {
        if (flowTryParseExportDefaultExpression()) {
            return;
        }
    }
    const functionStart = state.start;
    if (eat(TokenType._function)) {
        parseFunction(functionStart, true, true);
    }
    else if (isContextual(ContextualKeyword._async) && lookaheadType() === TokenType._function) {
        // async function declaration
        eatContextual(ContextualKeyword._async);
        eat(TokenType._function);
        parseFunction(functionStart, true, true);
    }
    else if (match(TokenType._class)) {
        parseClass(true, true);
    }
    else if (match(TokenType.at)) {
        parseDecorators();
        parseClass(true, true);
    }
    else {
        parseMaybeAssign();
        semicolon();
    }
}
function parseExportDeclaration() {
    if (isTypeScriptEnabled) {
        tsParseExportDeclaration();
    }
    else if (isFlowEnabled) {
        flowParseExportDeclaration();
    }
    else {
        parseStatement(true);
    }
}
function isExportDefaultSpecifier() {
    if (isTypeScriptEnabled && tsIsDeclarationStart()) {
        return false;
    }
    else if (isFlowEnabled && flowShouldDisallowExportDefaultSpecifier()) {
        return false;
    }
    if (match(TokenType.name)) {
        return state.contextualKeyword !== ContextualKeyword._async;
    }
    if (!match(TokenType._default)) {
        return false;
    }
    const _next = nextTokenStart();
    const lookahead = lookaheadTypeAndKeyword();
    const hasFrom = lookahead.type === TokenType.name && lookahead.contextualKeyword === ContextualKeyword._from;
    if (lookahead.type === TokenType.comma) {
        return true;
    }
    // lookahead again when `export default from` is seen
    if (hasFrom) {
        const nextAfterFrom = input.charCodeAt(nextTokenStartSince(_next + 4));
        return nextAfterFrom === charCodes.quotationMark || nextAfterFrom === charCodes.apostrophe;
    }
    return false;
}
function parseExportSpecifiersMaybe() {
    if (eat(TokenType.comma)) {
        parseExportSpecifiers();
    }
}
function parseExportFrom() {
    if (eatContextual(ContextualKeyword._from)) {
        parseExprAtom();
        maybeParseImportAttributes();
    }
    semicolon();
}
function shouldParseExportStar() {
    if (isFlowEnabled) {
        return flowShouldParseExportStar();
    }
    else {
        return match(TokenType.star);
    }
}
function parseExportStar() {
    if (isFlowEnabled) {
        flowParseExportStar();
    }
    else {
        baseParseExportStar();
    }
}
function baseParseExportStar() {
    expect(TokenType.star);
    if (isContextual(ContextualKeyword._as)) {
        parseExportNamespace();
    }
    else {
        parseExportFrom();
    }
}
function parseExportNamespace() {
    next();
    state.tokens[state.tokens.length - 1].type = TokenType._as;
    parseIdentifier();
    parseExportSpecifiersMaybe();
    parseExportFrom();
}
function shouldParseExportDeclaration() {
    return ((isTypeScriptEnabled && tsIsDeclarationStart()) ||
        (isFlowEnabled && flowShouldParseExportDeclaration()) ||
        state.type === TokenType._var ||
        state.type === TokenType._const ||
        state.type === TokenType._let ||
        state.type === TokenType._function ||
        state.type === TokenType._class ||
        isContextual(ContextualKeyword._async) ||
        match(TokenType.at));
}
// Parses a comma-separated list of module exports.
function parseExportSpecifiers() {
    let first = true;
    // export { x, y as z } [from '...']
    expect(TokenType.braceL);
    while (!eat(TokenType.braceR) && !state.error) {
        if (first) {
            first = false;
        }
        else {
            expect(TokenType.comma);
            if (eat(TokenType.braceR)) {
                break;
            }
        }
        parseExportSpecifier();
    }
}
function parseExportSpecifier() {
    if (isTypeScriptEnabled) {
        tsParseExportSpecifier();
        return;
    }
    parseIdentifier();
    state.tokens[state.tokens.length - 1].identifierRole = IdentifierRole.ExportAccess;
    if (eatContextual(ContextualKeyword._as)) {
        parseIdentifier();
    }
}
/**
 * Starting at the `module` token in an import, determine if it was truly an
 * import reflection token or just looks like one.
 *
 * Returns true for:
 * import module foo from "foo";
 * import module from from "foo";
 *
 * Returns false for:
 * import module from "foo";
 * import module, {bar} from "foo";
 */
function isImportReflection() {
    const snapshot = state.snapshot();
    expectContextual(ContextualKeyword._module);
    if (eatContextual(ContextualKeyword._from)) {
        if (isContextual(ContextualKeyword._from)) {
            state.restoreFromSnapshot(snapshot);
            return true;
        }
        else {
            state.restoreFromSnapshot(snapshot);
            return false;
        }
    }
    else if (match(TokenType.comma)) {
        state.restoreFromSnapshot(snapshot);
        return false;
    }
    else {
        state.restoreFromSnapshot(snapshot);
        return true;
    }
}
/**
 * Eat the "module" token from the import reflection proposal.
 * https://github.com/tc39/proposal-import-reflection
 */
function parseMaybeImportReflection() {
    // isImportReflection does snapshot/restore, so only run it if we see the word
    // "module".
    if (isContextual(ContextualKeyword._module) && isImportReflection()) {
        next();
    }
}
// Parses import declaration.
function parseImport() {
    if (isTypeScriptEnabled && match(TokenType.name) && lookaheadType() === TokenType.eq) {
        tsParseImportEqualsDeclaration();
        return;
    }
    if (isTypeScriptEnabled && isContextual(ContextualKeyword._type)) {
        const lookahead = lookaheadTypeAndKeyword();
        if (lookahead.type === TokenType.name && lookahead.contextualKeyword !== ContextualKeyword._from) {
            // One of these `import type` cases:
            // import type T = require('T');
            // import type A from 'A';
            expectContextual(ContextualKeyword._type);
            if (lookaheadType() === TokenType.eq) {
                tsParseImportEqualsDeclaration();
                return;
            }
            // If this is an `import type...from` statement, then we already ate the
            // type token, so proceed to the regular import parser.
        }
        else if (lookahead.type === TokenType.star || lookahead.type === TokenType.braceL) {
            // One of these `import type` cases, in which case we can eat the type token
            // and proceed as normal:
            // import type * as A from 'A';
            // import type {a} from 'A';
            expectContextual(ContextualKeyword._type);
        }
        // Otherwise, we are importing the name "type".
    }
    // import '...'
    if (match(TokenType.string)) {
        parseExprAtom();
    }
    else {
        parseMaybeImportReflection();
        parseImportSpecifiers();
        expectContextual(ContextualKeyword._from);
        parseExprAtom();
    }
    maybeParseImportAttributes();
    semicolon();
}
// eslint-disable-next-line no-unused-vars
function shouldParseDefaultImport() {
    return match(TokenType.name);
}
function parseImportSpecifierLocal() {
    parseImportedIdentifier();
}
// Parses a comma-separated list of module imports.
function parseImportSpecifiers() {
    if (isFlowEnabled) {
        flowStartParseImportSpecifiers();
    }
    let first = true;
    if (shouldParseDefaultImport()) {
        // import defaultObj, { x, y as z } from '...'
        parseImportSpecifierLocal();
        if (!eat(TokenType.comma))
            return;
    }
    if (match(TokenType.star)) {
        next();
        expectContextual(ContextualKeyword._as);
        parseImportSpecifierLocal();
        return;
    }
    expect(TokenType.braceL);
    while (!eat(TokenType.braceR) && !state.error) {
        if (first) {
            first = false;
        }
        else {
            // Detect an attempt to deep destructure
            if (eat(TokenType.colon)) {
                unexpected("ES2015 named imports do not destructure. Use another statement for destructuring after the import.");
            }
            expect(TokenType.comma);
            if (eat(TokenType.braceR)) {
                break;
            }
        }
        parseImportSpecifier();
    }
}
function parseImportSpecifier() {
    if (isTypeScriptEnabled) {
        tsParseImportSpecifier();
        return;
    }
    if (isFlowEnabled) {
        flowParseImportSpecifier();
        return;
    }
    parseImportedIdentifier();
    if (isContextual(ContextualKeyword._as)) {
        state.tokens[state.tokens.length - 1].identifierRole = IdentifierRole.ImportAccess;
        next();
        parseImportedIdentifier();
    }
}
/**
 * Parse import attributes like `with {type: "json"}`, or the legacy form
 * `assert {type: "json"}`.
 *
 * Import attributes technically have their own syntax, but are always parseable
 * as a plain JS object, so just do that for simplicity.
 */
function maybeParseImportAttributes() {
    if (match(TokenType._with) || (isContextual(ContextualKeyword._assert) && !hasPrecedingLineBreak())) {
        next();
        parseObj(false, false);
    }
}

function parseFile() {
    // If enabled, skip leading hashbang line.
    if (state.pos === 0 &&
        input.charCodeAt(0) === charCodes.numberSign &&
        input.charCodeAt(1) === charCodes.exclamationMark) {
        skipLineComment(2);
    }
    nextToken();
    return parseTopLevel();
}

class File {
    tokens;
    scopes;
    constructor(tokens, scopes) {
        this.tokens = tokens;
        this.scopes = scopes;
    }
}
function parse(input, isJSXEnabled, isTypeScriptEnabled, isFlowEnabled) {
    if (isFlowEnabled && isTypeScriptEnabled) {
        throw new Error("Cannot combine flow and typescript plugins.");
    }
    initParser(input, isJSXEnabled, isTypeScriptEnabled, isFlowEnabled);
    const result = parseFile();
    if (state.error) {
        throw augmentError(state.error);
    }
    return result;
}

export { File, parse };
