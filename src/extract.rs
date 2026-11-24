// Language: Rust 2021 | File: src/extract.rs | Target: Pure Rust HTML5 CSS3, XPath 1.0, JSON Path & DFA Regex Extraction Engine
//! Zero-Python-dependency extraction layer embedded directly in `http_tls._core`:
//! - WHATWG HTML5 DOM parsing & CSS3 selectors (`:has()`, `:contains()`, `:has-text()`, `::text`, `::attr(name)`) via `dom_query` (`html5ever`)
//! - Native Rust XPath 1.0 evaluator walking `dom_query::NodeRef` directly (axes, predicates, functions, unions)
//! - Linear-time DFA regex extraction (`re`, `re_first`) & delimiter slicing (`between`) via `regex`
//! - Structured JSON path extraction (`json_path`) supporting dot paths, negative indices, and `[*]` wildcards via `serde_json`

use dom_query::{Document, Matcher, NodeId, NodeRef, Selection};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use regex::Regex;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};

/// Thread-safe confinement wrapper around `dom_query::Document`.
///
/// # Safety
/// Every read/traversal of the inner `Document` (including its non-atomic `StrTendril`
/// and `RefCell` internals) occurs strictly while holding the enclosing `Mutex`, and
/// zero `NodeRef`/`Tendril` references ever escape the lock guard (PyO3 methods return
/// only owned `String`s, `HashMap<String, String>`, and `NodeId` values). `Arc`
/// guarantees exclusive drop on whichever thread releases the final reference.
struct SendDoc(Document);
unsafe impl Send for SendDoc {}

type SharedDoc = Arc<Mutex<SendDoc>>;

// ---------------------------------------------------------------------------
// CSS3 Pseudo-Element Parsing (::text, ::attr(name))
// ---------------------------------------------------------------------------
enum CssExtractMode {
    Elements,
    Text,
    Attr(String),
}

fn split_css_pseudo(raw: &str) -> (&str, CssExtractMode) {
    let trimmed = raw.trim();
    if let Some(base) = trimmed.strip_suffix("::text") {
        let b = base.trim();
        return (if b.is_empty() { "*" } else { b }, CssExtractMode::Text);
    }
    if let Some(idx) = trimmed.rfind("::attr(") {
        if trimmed.ends_with(')') {
            let attr_name = trimmed[idx + 7..trimmed.len() - 1]
                .trim()
                .trim_matches(|c| c == '"' || c == '\'');
            let base = trimmed[..idx].trim();
            return (
                if base.is_empty() { "*" } else { base },
                CssExtractMode::Attr(attr_name.to_string()),
            );
        }
    }
    (trimmed, CssExtractMode::Elements)
}

fn run_css_on_selection<'py>(
    py: Python<'py>,
    doc: &SharedDoc,
    sel: Selection<'_>,
    selector: &str,
    first_only: bool,
) -> PyResult<Vec<Py<PyAny>>> {
    let (css_expr, mode) = split_css_pseudo(selector);
    let matcher = Matcher::new(css_expr)
        .map_err(|_| PyValueError::new_err(format!("Invalid CSS selector: '{css_expr}'")))?;
    let matched = sel.select_matcher(&matcher);
    let mut out = Vec::new();
    for node in matched.nodes() {
        match &mode {
            CssExtractMode::Elements => {
                let elem = NativeElement {
                    doc: Arc::clone(doc),
                    id: node.id,
                };
                out.push(Py::new(py, elem)?.into_any());
            }
            CssExtractMode::Text => {
                out.push(node.text().to_string().into_pyobject(py)?.into_any().unbind());
            }
            CssExtractMode::Attr(name) => {
                if let Some(val) = node.attr(name) {
                    out.push(val.to_string().into_pyobject(py)?.into_any().unbind());
                } else {
                    continue;
                }
            }
        }
        if first_only {
            break;
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Native Rust XPath 1.0 Evaluator over dom_query HTML5 DOM
// ---------------------------------------------------------------------------
#[derive(Clone, Debug)]
enum XPathAxis {
    Child,
    Descendant,
    DescendantOrSelf,
    SelfAxis,
    Parent,
    Ancestor,
    AncestorOrSelf,
    FollowingSibling,
    PrecedingSibling,
    Following,
    Preceding,
    Attribute,
}

#[derive(Clone, Debug)]
enum XPathNodeTest {
    AnyElement,
    Tag(String),
    AnyNode,
    Text,
    Attr(String),
    AnyAttr,
}

#[derive(Clone, Debug)]
struct XPathStep {
    axis: XPathAxis,
    test: XPathNodeTest,
    predicates: Vec<String>,
}

enum XPathValue {
    Node(NodeId),
    Str(String),
}

fn split_top_level(s: &str, sep: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut depth_sq = 0i32;
    let mut depth_pr = 0i32;
    let mut quote: Option<char> = None;
    for (i, ch) in s.char_indices() {
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '[' => depth_sq += 1,
            ']' => depth_sq = (depth_sq - 1).max(0),
            '(' => depth_pr += 1,
            ')' => depth_pr = (depth_pr - 1).max(0),
            c if c == sep && depth_sq == 0 && depth_pr == 0 => {
                parts.push(s[start..i].trim().to_string());
                start = i + ch.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(s[start..].trim().to_string());
    parts
}

fn split_top_level_keyword(s: &str, kw: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let bytes = s.as_bytes();
    let kw_bytes = kw.as_bytes();
    let mut start = 0usize;
    let mut depth_sq = 0i32;
    let mut depth_pr = 0i32;
    let mut quote: Option<u8> = None;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if b == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'\'' | b'"' => quote = Some(b),
            b'[' => depth_sq += 1,
            b']' => depth_sq = (depth_sq - 1).max(0),
            b'(' => depth_pr += 1,
            b')' => depth_pr = (depth_pr - 1).max(0),
            _ if depth_sq == 0
                && depth_pr == 0
                && i + kw_bytes.len() <= bytes.len()
                && bytes[i..i + kw_bytes.len()].eq_ignore_ascii_case(kw_bytes) =>
            {
                let left_ok = i == 0
                    || bytes[i - 1].is_ascii_whitespace()
                    || bytes[i - 1] == b')'
                    || bytes[i - 1] == b']';
                let right_idx = i + kw_bytes.len();
                let right_ok = right_idx == bytes.len()
                    || bytes[right_idx].is_ascii_whitespace()
                    || bytes[right_idx] == b'('
                    || bytes[right_idx] == b'[';
                if left_ok && right_ok {
                    parts.push(s[start..i].trim().to_string());
                    start = right_idx;
                    i = right_idx;
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }
    if !parts.is_empty() {
        parts.push(s[start..].trim().to_string());
    }
    parts
}

fn find_top_level_op(s: &str, op: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let op_bytes = op.as_bytes();
    let mut depth_sq = 0i32;
    let mut depth_pr = 0i32;
    let mut quote: Option<u8> = None;
    let mut i = 0usize;
    while i + op_bytes.len() <= bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if b == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'\'' | b'"' => quote = Some(b),
            b'[' => depth_sq += 1,
            b']' => depth_sq = (depth_sq - 1).max(0),
            b'(' => depth_pr += 1,
            b')' => depth_pr = (depth_pr - 1).max(0),
            _ if depth_sq == 0 && depth_pr == 0 && &bytes[i..i + op_bytes.len()] == op_bytes => {
                // Prevent '=' from matching inside '!=', '<=', '>='
                if op == "=" {
                    let prev = if i > 0 { bytes[i - 1] } else { 0 };
                    if prev == b'!' || prev == b'<' || prev == b'>' {
                        i += 1;
                        continue;
                    }
                }
                if op == "<" || op == ">" {
                    let next = bytes.get(i + 1).copied().unwrap_or(0);
                    if next == b'=' {
                        i += 2;
                        continue;
                    }
                }
                return Some(i);
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn parse_xpath_steps(expr: &str) -> Result<(bool, Vec<XPathStep>), String> {
    let mut s = expr.trim();
    if s.is_empty() {
        return Err("Empty XPath expression".to_string());
    }
    let is_abs = s.starts_with('/');
    let mut steps = Vec::new();
    let mut next_descendant = false;

    if let Some(rest) = s.strip_prefix("//") {
        next_descendant = true;
        s = rest;
    } else if let Some(rest) = s.strip_prefix('/') {
        s = rest;
    }

    // Tokenize path steps respecting quotes and [...]
    let mut i = 0usize;
    let bytes = s.as_bytes();
    while i < bytes.len() {
        let step_start = i;
        let mut depth_sq = 0i32;
        let mut depth_pr = 0i32;
        let mut quote: Option<u8> = None;
        while i < bytes.len() {
            let b = bytes[i];
            if let Some(q) = quote {
                if b == q {
                    quote = None;
                }
                i += 1;
                continue;
            }
            match b {
                b'\'' | b'"' => quote = Some(b),
                b'[' => depth_sq += 1,
                b']' => depth_sq = (depth_sq - 1).max(0),
                b'(' => depth_pr += 1,
                b')' => depth_pr = (depth_pr - 1).max(0),
                b'/' if depth_sq == 0 && depth_pr == 0 => break,
                _ => {}
            }
            i += 1;
        }
        let raw_step = s[step_start..i].trim();
        let cur_desc = next_descendant;
        next_descendant = false;
        if i < bytes.len() && bytes[i] == b'/' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                next_descendant = true;
                i += 2;
            } else {
                i += 1;
            }
        }
        if raw_step.is_empty() {
            continue;
        }
        steps.push(parse_single_step(raw_step, cur_desc)?);
    }

    Ok((is_abs, steps))
}

fn parse_single_step(raw: &str, descendant: bool) -> Result<XPathStep, String> {
    if raw == "." {
        return Ok(XPathStep {
            axis: XPathAxis::SelfAxis,
            test: XPathNodeTest::AnyNode,
            predicates: Vec::new(),
        });
    }
    if raw == ".." {
        return Ok(XPathStep {
            axis: XPathAxis::Parent,
            test: XPathNodeTest::AnyNode,
            predicates: Vec::new(),
        });
    }

    // Extract node-test head and chained `[...]` predicates
    let mut predicates = Vec::new();
    let bytes = raw.as_bytes();
    let mut idx = 0usize;
    let mut quote: Option<u8> = None;
    let mut depth_pr = 0i32;
    while idx < bytes.len() {
        let b = bytes[idx];
        if let Some(q) = quote {
            if b == q {
                quote = None;
            }
            idx += 1;
            continue;
        }
        match b {
            b'\'' | b'"' => quote = Some(b),
            b'(' => depth_pr += 1,
            b')' => depth_pr = (depth_pr - 1).max(0),
            b'[' if depth_pr == 0 => break,
            _ => {}
        }
        idx += 1;
    }
    let head_end = idx;
    let head = raw[..head_end].trim();

    while idx < bytes.len() {
        if bytes[idx] != b'[' {
            idx += 1;
            continue;
        }
        let p_start = idx + 1;
        let mut depth = 1i32;
        let mut q: Option<u8> = None;
        idx += 1;
        while idx < bytes.len() && depth > 0 {
            let b = bytes[idx];
            if let Some(qc) = q {
                if b == qc {
                    q = None;
                }
            } else {
                match b {
                    b'\'' | b'"' => q = Some(b),
                    b'[' => depth += 1,
                    b']' => depth -= 1,
                    _ => {}
                }
            }
            idx += 1;
        }
        if depth != 0 {
            return Err(format!("Unclosed '[' predicate in XPath step '{raw}'"));
        }
        predicates.push(raw[p_start..idx - 1].trim().to_string());
    }

    let (axis, test_str) = if let Some((ax, rest)) = head.split_once("::") {
        let parsed_axis = match ax.trim().to_ascii_lowercase().as_str() {
            "child" => XPathAxis::Child,
            "descendant" => XPathAxis::Descendant,
            "descendant-or-self" => XPathAxis::DescendantOrSelf,
            "self" => XPathAxis::SelfAxis,
            "parent" => XPathAxis::Parent,
            "ancestor" => XPathAxis::Ancestor,
            "ancestor-or-self" => XPathAxis::AncestorOrSelf,
            "following-sibling" => XPathAxis::FollowingSibling,
            "preceding-sibling" => XPathAxis::PrecedingSibling,
            "following" => XPathAxis::Following,
            "preceding" => XPathAxis::Preceding,
            "attribute" => XPathAxis::Attribute,
            other => return Err(format!("Unsupported XPath axis '{other}::'")),
        };
        (parsed_axis, rest.trim())
    } else if let Some(attr) = head.strip_prefix('@') {
        (XPathAxis::Attribute, attr.trim())
    } else if descendant {
        (XPathAxis::Descendant, head)
    } else {
        (XPathAxis::Child, head)
    };

    let test = if matches!(axis, XPathAxis::Attribute) {
        if test_str == "*" {
            XPathNodeTest::AnyAttr
        } else {
            XPathNodeTest::Attr(test_str.to_string())
        }
    } else {
        match test_str {
            "*" => XPathNodeTest::AnyElement,
            "node()" => XPathNodeTest::AnyNode,
            "text()" => XPathNodeTest::Text,
            tag if !tag.is_empty() => XPathNodeTest::Tag(tag.to_ascii_lowercase()),
            _ => return Err(format!("Invalid XPath node test in '{raw}'")),
        }
    };

    Ok(XPathStep {
        axis,
        test,
        predicates,
    })
}

fn direct_text_children(node: &NodeRef<'_>) -> Vec<String> {
    node.children()
        .into_iter()
        .filter(|c| c.is_text())
        .map(|c| c.text().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn all_text_descendants(node: &NodeRef<'_>) -> Vec<String> {
    node.descendants()
        .into_iter()
        .filter(|c| c.is_text())
        .map(|c| c.text().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn normalize_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn unquote_literal(s: &str) -> Option<String> {
    let t = s.trim();
    if t.len() >= 2
        && ((t.starts_with('"') && t.ends_with('"')) || (t.starts_with('\'') && t.ends_with('\'')))
    {
        Some(t[1..t.len() - 1].to_string())
    } else {
        None
    }
}

fn eval_xpath_string_expr(node: &NodeRef<'_>, expr: &str) -> String {
    let e = expr.trim();
    if let Some(lit) = unquote_literal(e) {
        return lit;
    }
    if e == "." || e == "string(.)" {
        return node.text().to_string();
    }
    if e == "text()" {
        let direct = direct_text_children(node).join("");
        if !direct.is_empty() {
            return direct;
        }
        return node.text().to_string();
    }
    if e == "name()" || e == "local-name()" {
        return node
            .node_name()
            .map(|n| n.to_string().to_ascii_lowercase())
            .unwrap_or_default();
    }
    if let Some(attr) = e.strip_prefix('@') {
        return node
            .attr(attr.trim())
            .map(|v| v.to_string())
            .unwrap_or_default();
    }
    if let Some(inner) = strip_func_call(e, "normalize-space") {
        let val = if inner.is_empty() {
            node.text().to_string()
        } else {
            eval_xpath_string_expr(node, inner)
        };
        return normalize_ws(&val);
    }
    if let Some(inner) = strip_func_call(e, "string") {
        return eval_xpath_string_expr(node, if inner.is_empty() { "." } else { inner });
    }
    if let Some(inner) = strip_func_call(e, "substring-before") {
        let args = split_top_level(inner, ',');
        if args.len() == 2 {
            let hay = eval_xpath_string_expr(node, &args[0]);
            let sep = eval_xpath_string_expr(node, &args[1]);
            if sep.is_empty() {
                return String::new();
            }
            return hay
                .find(&sep)
                .map(|idx| hay[..idx].to_string())
                .unwrap_or_default();
        }
    }
    if let Some(inner) = strip_func_call(e, "substring-after") {
        let args = split_top_level(inner, ',');
        if args.len() == 2 {
            let hay = eval_xpath_string_expr(node, &args[0]);
            let sep = eval_xpath_string_expr(node, &args[1]);
            if sep.is_empty() {
                return hay;
            }
            return hay
                .find(&sep)
                .map(|idx| hay[idx + sep.len()..].to_string())
                .unwrap_or_default();
        }
    }
    // Relative child/subpath string value (e.g. `span` or `.//a/@href`)
    if let Ok((_, steps)) = parse_xpath_steps(e) {
        if let Ok(vals) = eval_steps_from_nodes(node.tree, vec![node.id], &steps) {
            for v in vals {
                match v {
                    XPathValue::Str(s) => return s,
                    XPathValue::Node(id) => {
                        if let Some(nr) = node.tree.get(&id) {
                            return nr.text().to_string();
                        }
                    }
                }
            }
        }
    }
    String::new()
}

fn eval_xpath_number_expr(node: &NodeRef<'_>, expr: &str, pos: usize, last: usize) -> Option<f64> {
    let e = expr.trim();
    if e == "position()" {
        return Some(pos as f64);
    }
    if e == "last()" {
        return Some(last as f64);
    }
    if let Ok(n) = e.parse::<f64>() {
        return Some(n);
    }
    if let Some((lhs, rhs)) = e.split_once('-') {
        if !lhs.trim().is_empty() && !rhs.trim().is_empty() {
            if let (Some(a), Some(b)) = (
                eval_xpath_number_expr(node, lhs, pos, last),
                eval_xpath_number_expr(node, rhs, pos, last),
            ) {
                return Some(a - b);
            }
        }
    }
    if let Some((lhs, rhs)) = e.split_once('+') {
        if let (Some(a), Some(b)) = (
            eval_xpath_number_expr(node, lhs, pos, last),
            eval_xpath_number_expr(node, rhs, pos, last),
        ) {
            return Some(a + b);
        }
    }
    if let Some(inner) = strip_func_call(e, "string-length") {
        let s = eval_xpath_string_expr(node, if inner.is_empty() { "." } else { inner });
        return Some(s.chars().count() as f64);
    }
    if let Some(inner) = strip_func_call(e, "count") {
        if let Ok((_, steps)) = parse_xpath_steps(inner) {
            if let Ok(vals) = eval_steps_from_nodes(node.tree, vec![node.id], &steps) {
                return Some(vals.len() as f64);
            }
        }
    }
    None
}

fn strip_func_call<'a>(expr: &'a str, name: &str) -> Option<&'a str> {
    let t = expr.trim();
    if t.len() <= name.len() + 2 || !t.ends_with(')') {
        return None;
    }
    let prefix = &t[..name.len()];
    if prefix.eq_ignore_ascii_case(name) && t.as_bytes()[name.len()] == b'(' {
        Some(t[name.len() + 1..t.len() - 1].trim())
    } else {
        None
    }
}

fn unwrap_outer_parens(s: &str) -> &str {
    let mut cur = s.trim();
    loop {
        if !(cur.starts_with('(') && cur.ends_with(')')) {
            return cur;
        }
        let bytes = cur.as_bytes();
        let mut depth = 0i32;
        let mut q: Option<u8> = None;
        let mut matched_end = false;
        for (i, &b) in bytes.iter().enumerate() {
            if let Some(qc) = q {
                if b == qc {
                    q = None;
                }
                continue;
            }
            match b {
                b'\'' | b'"' => q = Some(b),
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        matched_end = i == bytes.len() - 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        if matched_end {
            cur = cur[1..cur.len() - 1].trim();
        } else {
            return cur;
        }
    }
}

fn eval_xpath_predicate(node: &NodeRef<'_>, pred: &str, pos: usize, last: usize) -> bool {
    let e = unwrap_outer_parens(pred);
    if e.is_empty() {
        return true;
    }

    // 1. Boolean OR (lowest precedence)
    let or_parts = split_top_level_keyword(e, "or");
    if or_parts.len() > 1 {
        return or_parts
            .iter()
            .any(|p| eval_xpath_predicate(node, p, pos, last));
    }

    // 2. Boolean AND
    let and_parts = split_top_level_keyword(e, "and");
    if and_parts.len() > 1 {
        return and_parts
            .iter()
            .all(|p| eval_xpath_predicate(node, p, pos, last));
    }

    // 3. Negation `not(...)`
    if let Some(inner) = strip_func_call(e, "not") {
        return !eval_xpath_predicate(node, inner, pos, last);
    }

    // 4. Pure positional numeric expression: `[1]`, `[last()]`, `[last()-1]`
    if let Some(num) = eval_xpath_number_expr(node, e, pos, last) {
        return (pos as f64 - num).abs() < 1e-9;
    }

    // 5. Comparisons: !=, <=, >=, =, <, >
    for op in ["!=", "<=", ">=", "=", "<", ">"] {
        if let Some(idx) = find_top_level_op(e, op) {
            let lhs = e[..idx].trim();
            let rhs = e[idx + op.len()..].trim();
            if matches!(op, "<=" | ">=" | "<" | ">")
                || (eval_xpath_number_expr(node, lhs, pos, last).is_some()
                    && eval_xpath_number_expr(node, rhs, pos, last).is_some())
            {
                let a = eval_xpath_number_expr(node, lhs, pos, last)
                    .or_else(|| eval_xpath_string_expr(node, lhs).trim().parse::<f64>().ok());
                let b = eval_xpath_number_expr(node, rhs, pos, last)
                    .or_else(|| eval_xpath_string_expr(node, rhs).trim().parse::<f64>().ok());
                if let (Some(x), Some(y)) = (a, b) {
                    return match op {
                        "=" => (x - y).abs() < 1e-9,
                        "!=" => (x - y).abs() >= 1e-9,
                        "<" => x < y,
                        "<=" => x <= y,
                        ">" => x > y,
                        ">=" => x >= y,
                        _ => false,
                    };
                }
            }
            let sa = eval_xpath_string_expr(node, lhs);
            let sb = eval_xpath_string_expr(node, rhs);
            return match op {
                "=" => sa == sb,
                "!=" => sa != sb,
                _ => false,
            };
        }
    }

    // 6. String/boolean functions: contains, starts-with, ends-with
    if let Some(inner) = strip_func_call(e, "contains") {
        let args = split_top_level(inner, ',');
        if args.len() == 2 {
            let hay = eval_xpath_string_expr(node, &args[0]);
            let needle = eval_xpath_string_expr(node, &args[1]);
            return hay.contains(&needle);
        }
    }
    if let Some(inner) = strip_func_call(e, "starts-with") {
        let args = split_top_level(inner, ',');
        if args.len() == 2 {
            let hay = eval_xpath_string_expr(node, &args[0]);
            let needle = eval_xpath_string_expr(node, &args[1]);
            return hay.starts_with(&needle);
        }
    }
    if let Some(inner) = strip_func_call(e, "ends-with") {
        let args = split_top_level(inner, ',');
        if args.len() == 2 {
            let hay = eval_xpath_string_expr(node, &args[0]);
            let needle = eval_xpath_string_expr(node, &args[1]);
            return hay.ends_with(&needle);
        }
    }

    // 7. Attribute presence `[@href]`
    if let Some(attr) = e.strip_prefix('@') {
        return node.attr(attr.trim()).is_some();
    }

    // 8. Child/subpath existence `[span]` or `[a[@href]]`
    if let Ok((_, steps)) = parse_xpath_steps(e) {
        if let Ok(vals) = eval_steps_from_nodes(node.tree, vec![node.id], &steps) {
            return !vals.is_empty();
        }
    }

    false
}

fn node_matches_test(node: &NodeRef<'_>, test: &XPathNodeTest) -> bool {
    match test {
        XPathNodeTest::AnyElement => node.is_element(),
        XPathNodeTest::AnyNode => true,
        XPathNodeTest::Tag(tag) => {
            node.is_element()
                && node
                    .node_name()
                    .map(|n| n.eq_ignore_ascii_case(tag))
                    .unwrap_or(false)
        }
        XPathNodeTest::Text => node.is_text(),
        XPathNodeTest::Attr(_) | XPathNodeTest::AnyAttr => false,
    }
}

fn eval_steps_from_nodes(
    tree: &dom_query::Tree,
    initial: Vec<NodeId>,
    steps: &[XPathStep],
) -> Result<Vec<XPathValue>, String> {
    let mut current: Vec<NodeId> = initial;
    let mut str_results: Option<Vec<String>> = None;

    for (step_idx, step) in steps.iter().enumerate() {
        let is_last_step = step_idx + 1 == steps.len();

        // Attribute extraction step (`@href`, `@*`)
        if matches!(step.axis, XPathAxis::Attribute) {
            let mut strs = Vec::new();
            for &nid in &current {
                let Some(nr) = tree.get(&nid) else { continue };
                if !nr.is_element() {
                    continue;
                }
                match &step.test {
                    XPathNodeTest::Attr(name) => {
                        if let Some(val) = nr.attr(name) {
                            strs.push(val.to_string());
                        }
                    }
                    XPathNodeTest::AnyAttr => {
                        for attr in nr.attrs() {
                            strs.push(attr.value.to_string());
                        }
                    }
                    _ => {}
                }
            }
            if !step.predicates.is_empty() {
                let total = strs.len();
                let mut filtered = Vec::new();
                for (i, s) in strs.into_iter().enumerate() {
                    let pos = i + 1;
                    let mut keep = true;
                    for p in &step.predicates {
                        if let Ok(n) = p.trim().parse::<usize>() {
                            if pos != n {
                                keep = false;
                                break;
                            }
                        } else if p.trim() == "last()" && pos != total {
                            keep = false;
                            break;
                        }
                    }
                    if keep {
                        filtered.push(s);
                    }
                }
                strs = filtered;
            }
            str_results = Some(strs);
            current.clear();
            if !is_last_step {
                return Err("Cannot traverse child steps after an attribute selector".to_string());
            }
            break;
        }

        // Text extraction step (`text()`)
        if matches!(step.test, XPathNodeTest::Text) {
            let mut strs = Vec::new();
            for &nid in &current {
                let Some(nr) = tree.get(&nid) else { continue };
                let texts = match step.axis {
                    XPathAxis::Descendant | XPathAxis::DescendantOrSelf => all_text_descendants(&nr),
                    _ => direct_text_children(&nr),
                };
                strs.extend(texts);
            }
            if !step.predicates.is_empty() {
                let total = strs.len();
                let mut filtered = Vec::new();
                for (i, s) in strs.into_iter().enumerate() {
                    let pos = i + 1;
                    let mut keep = true;
                    for p in &step.predicates {
                        if let Ok(n) = p.trim().parse::<usize>() {
                            if pos != n {
                                keep = false;
                                break;
                            }
                        } else if p.trim() == "last()" && pos != total {
                            keep = false;
                            break;
                        }
                    }
                    if keep {
                        filtered.push(s);
                    }
                }
                strs = filtered;
            }
            str_results = Some(strs);
            current.clear();
            if !is_last_step {
                return Err("Cannot traverse child steps after text()".to_string());
            }
            break;
        }

        let mut next_nodes = Vec::new();
        let mut seen = HashSet::new();

        for &nid in &current {
            let Some(nr) = tree.get(&nid) else { continue };
            let mut candidates: Vec<NodeId> = Vec::new();
            match step.axis {
                XPathAxis::SelfAxis => {
                    if node_matches_test(&nr, &step.test) {
                        candidates.push(nr.id);
                    }
                }
                XPathAxis::Child => {
                    for c in nr.children() {
                        if node_matches_test(&c, &step.test) {
                            candidates.push(c.id);
                        }
                    }
                }
                XPathAxis::Descendant => {
                    for d in nr.descendants() {
                        if node_matches_test(&d, &step.test) {
                            candidates.push(d.id);
                        }
                    }
                }
                XPathAxis::DescendantOrSelf => {
                    if node_matches_test(&nr, &step.test) {
                        candidates.push(nr.id);
                    }
                    for d in nr.descendants() {
                        if node_matches_test(&d, &step.test) {
                            candidates.push(d.id);
                        }
                    }
                }
                XPathAxis::Parent => {
                    if let Some(p) = nr.parent() {
                        if node_matches_test(&p, &step.test) {
                            candidates.push(p.id);
                        }
                    }
                }
                XPathAxis::Ancestor => {
                    for a in nr.ancestors(None) {
                        if node_matches_test(&a, &step.test) {
                            candidates.push(a.id);
                        }
                    }
                }
                XPathAxis::AncestorOrSelf => {
                    if node_matches_test(&nr, &step.test) {
                        candidates.push(nr.id);
                    }
                    for a in nr.ancestors(None) {
                        if node_matches_test(&a, &step.test) {
                            candidates.push(a.id);
                        }
                    }
                }
                XPathAxis::FollowingSibling => {
                    let mut cur_sib = nr.next_sibling();
                    while let Some(sib) = cur_sib {
                        if node_matches_test(&sib, &step.test) {
                            candidates.push(sib.id);
                        }
                        cur_sib = sib.next_sibling();
                    }
                }
                XPathAxis::PrecedingSibling => {
                    let mut cur_sib = nr.prev_sibling();
                    while let Some(sib) = cur_sib {
                        if node_matches_test(&sib, &step.test) {
                            candidates.push(sib.id);
                        }
                        cur_sib = sib.prev_sibling();
                    }
                }
                XPathAxis::Following => {
                    // Document order: all following siblings (and their descendants) of self and ancestors
                    let mut chain = vec![nr];
                    chain.extend(nr.ancestors(None));
                    for anc in chain {
                        let mut cur_sib = anc.next_sibling();
                        while let Some(sib) = cur_sib {
                            if node_matches_test(&sib, &step.test) {
                                candidates.push(sib.id);
                            }
                            for d in sib.descendants() {
                                if node_matches_test(&d, &step.test) {
                                    candidates.push(d.id);
                                }
                            }
                            cur_sib = sib.next_sibling();
                        }
                    }
                }
                XPathAxis::Preceding => {
                    // Reverse document order: nearest preceding nodes first (excluding ancestors)
                    let mut chain = vec![nr];
                    chain.extend(nr.ancestors(None));
                    for anc in chain {
                        let mut cur_sib = anc.prev_sibling();
                        while let Some(sib) = cur_sib {
                            let descs = sib.descendants();
                            for d in descs.into_iter().rev() {
                                if node_matches_test(&d, &step.test) {
                                    candidates.push(d.id);
                                }
                            }
                            if node_matches_test(&sib, &step.test) {
                                candidates.push(sib.id);
                            }
                            cur_sib = sib.prev_sibling();
                        }
                    }
                }
                XPathAxis::Attribute => {}
            }

            // Apply predicates sequentially to this candidate axis set
            for pred in &step.predicates {
                let last = candidates.len();
                let mut filtered = Vec::with_capacity(candidates.len());
                for (i, cid) in candidates.into_iter().enumerate() {
                    if let Some(cnr) = tree.get(&cid) {
                        if eval_xpath_predicate(&cnr, pred, i + 1, last) {
                            filtered.push(cid);
                        }
                    }
                }
                candidates = filtered;
            }

            for cid in candidates {
                if seen.insert(cid) {
                    next_nodes.push(cid);
                }
            }
        }
        current = next_nodes;
    }

    if let Some(strs) = str_results {
        Ok(strs.into_iter().map(XPathValue::Str).collect())
    } else {
        Ok(current.into_iter().map(XPathValue::Node).collect())
    }
}

fn split_leading_predicates(s: &str) -> Result<(Vec<String>, &str), String> {
    let mut preds = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'[' {
            break;
        }
        let start = i + 1;
        let mut depth = 1i32;
        let mut quote: Option<u8> = None;
        i += 1;
        while i < bytes.len() && depth > 0 {
            let b = bytes[i];
            if let Some(q) = quote {
                if b == q {
                    quote = None;
                }
            } else {
                match b {
                    b'\'' | b'"' => quote = Some(b),
                    b'[' => depth += 1,
                    b']' => depth -= 1,
                    _ => {}
                }
            }
            i += 1;
        }
        if depth != 0 {
            return Err(format!("Unclosed '[' predicate in '{s}'"));
        }
        preds.push(s[start..i - 1].trim().to_string());
    }
    Ok((preds, s[i..].trim()))
}

fn eval_xpath_branch(
    tree: &dom_query::Tree,
    context_id: NodeId,
    branch: &str,
) -> Result<Vec<XPathValue>, String> {
    let trimmed = branch.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    // Support parenthesized XPath groups such as `(//div[@class='card'])[1]/@data-id`
    if trimmed.starts_with('(') {
        let bytes = trimmed.as_bytes();
        let mut depth = 0i32;
        let mut quote: Option<u8> = None;
        let mut close_idx = None;
        for (i, &b) in bytes.iter().enumerate() {
            if let Some(q) = quote {
                if b == q {
                    quote = None;
                }
                continue;
            }
            match b {
                b'\'' | b'"' => quote = Some(b),
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        close_idx = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(cidx) = close_idx else {
            return Err(format!("Unclosed '(' in XPath '{trimmed}'"));
        };
        let inner = trimmed[1..cidx].trim();
        let after = trimmed[cidx + 1..].trim();

        let mut group_vals = Vec::new();
        let mut seen = HashSet::new();
        for sub in split_top_level(inner, '|') {
            for v in eval_xpath_branch(tree, context_id, &sub)? {
                match &v {
                    XPathValue::Node(id) => {
                        if seen.insert(*id) {
                            group_vals.push(v);
                        }
                    }
                    XPathValue::Str(_) => group_vals.push(v),
                }
            }
        }

        let (preds, tail) = split_leading_predicates(after)?;
        for pred in &preds {
            let total = group_vals.len();
            let mut filtered = Vec::with_capacity(total);
            for (idx, val) in group_vals.into_iter().enumerate() {
                let pos = idx + 1;
                let keep = match &val {
                    XPathValue::Node(nid) => tree
                        .get(nid)
                        .map(|nr| eval_xpath_predicate(&nr, pred, pos, total))
                        .unwrap_or(false),
                    XPathValue::Str(_) => {
                        if let Ok(n) = pred.trim().parse::<usize>() {
                            pos == n
                        } else if pred.trim() == "last()" {
                            pos == total
                        } else {
                            true
                        }
                    }
                };
                if keep {
                    filtered.push(val);
                }
            }
            group_vals = filtered;
        }

        if tail.is_empty() {
            return Ok(group_vals);
        }
        let Some(rel_expr) = tail.strip_prefix('/') else {
            return Err(format!("Unexpected trailing XPath token '{tail}'"));
        };
        let node_ids: Vec<NodeId> = group_vals
            .into_iter()
            .filter_map(|v| match v {
                XPathValue::Node(id) => Some(id),
                XPathValue::Str(_) => None,
            })
            .collect();
        if node_ids.is_empty() {
            return Ok(Vec::new());
        }
        // Preserve leading `//` as descendant step when tail was `//...`
        let step_expr = if tail.starts_with("//") {
            format!(".{tail}")
        } else {
            rel_expr.to_string()
        };
        let (_, steps) = parse_xpath_steps(&step_expr)?;
        return eval_steps_from_nodes(tree, node_ids, &steps);
    }

    let (is_abs, steps) = parse_xpath_steps(trimmed)?;
    let start_id = if is_abs { tree.root().id } else { context_id };
    eval_steps_from_nodes(tree, vec![start_id], &steps)
}

fn eval_xpath<'py>(
    py: Python<'py>,
    doc_arc: &SharedDoc,
    context_id: Option<NodeId>,
    expr: &str,
    first_only: bool,
) -> PyResult<Vec<Py<PyAny>>> {
    let guard = doc_arc.lock().unwrap_or_else(|e| e.into_inner());
    let doc = &guard.0;
    let branches = split_top_level(expr.trim(), '|');
    let mut out = Vec::new();
    let mut seen_nodes = HashSet::new();
    let ctx_id = context_id.unwrap_or_else(|| doc.tree.root().id);

    for branch in branches {
        if branch.is_empty() {
            continue;
        }
        let vals = eval_xpath_branch(&doc.tree, ctx_id, &branch)
            .map_err(|e| PyValueError::new_err(format!("XPath evaluation failed '{expr}': {e}")))?;

        for val in vals {
            match val {
                XPathValue::Str(s) => {
                    out.push(s.into_pyobject(py)?.into_any().unbind());
                }
                XPathValue::Node(id) => {
                    if seen_nodes.insert(id) {
                        let elem = NativeElement {
                            doc: Arc::clone(doc_arc),
                            id,
                        };
                        out.push(Py::new(py, elem)?.into_any());
                    } else {
                        continue;
                    }
                }
            }
            if first_only {
                return Ok(out);
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Regex (Linear-Time DFA w/ Bounded Cache), Delimiter Slicing & JSON Path
// ---------------------------------------------------------------------------
const REGEX_CACHE_LIMIT: usize = 128;

fn get_cached_regex(pattern: &str) -> PyResult<Regex> {
    static CACHE: OnceLock<Mutex<HashMap<String, Regex>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    {
        let guard = cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(re) = guard.get(pattern) {
            return Ok(re.clone());
        }
    }
    let compiled = Regex::new(pattern)
        .map_err(|e| PyValueError::new_err(format!("Invalid regex pattern '{pattern}': {e}")))?;
    let mut guard = cache.lock().unwrap_or_else(|e| e.into_inner());
    if guard.len() >= REGEX_CACHE_LIMIT {
        guard.clear();
    }
    guard.insert(pattern.to_string(), compiled.clone());
    Ok(compiled)
}

#[pyfunction]
pub fn extract_re(text: &str, pattern: &str) -> PyResult<Vec<String>> {
    let re = get_cached_regex(pattern)?;
    let has_groups = re.captures_len() > 1;
    let mut out = Vec::new();
    if has_groups {
        for caps in re.captures_iter(text) {
            if let Some(m) = caps.get(1) {
                out.push(m.as_str().to_string());
            } else {
                // Fallback to first matched optional group or full match
                let found = (2..caps.len()).find_map(|i| caps.get(i)).or_else(|| caps.get(0));
                if let Some(m) = found {
                    out.push(m.as_str().to_string());
                }
            }
        }
    } else {
        for m in re.find_iter(text) {
            out.push(m.as_str().to_string());
        }
    }
    Ok(out)
}

#[pyfunction]
pub fn extract_re_first(text: &str, pattern: &str) -> PyResult<Option<String>> {
    let re = get_cached_regex(pattern)?;
    if re.captures_len() > 1 {
        if let Some(caps) = re.captures(text) {
            if let Some(m) = caps.get(1) {
                return Ok(Some(m.as_str().to_string()));
            }
            let found = (2..caps.len()).find_map(|i| caps.get(i)).or_else(|| caps.get(0));
            return Ok(found.map(|m| m.as_str().to_string()));
        }
        Ok(None)
    } else {
        Ok(re.find(text).map(|m| m.as_str().to_string()))
    }
}

#[pyfunction]
pub fn extract_between(text: &str, left: &str, right: &str) -> Option<String> {
    let start = if left.is_empty() {
        0
    } else {
        text.find(left)? + left.len()
    };
    let rest = &text[start..];
    if right.is_empty() {
        Some(rest.to_string())
    } else {
        let end = rest.find(right)?;
        Some(rest[..end].to_string())
    }
}

#[pyfunction]
pub fn extract_between_all(text: &str, left: &str, right: &str) -> Vec<String> {
    if left.is_empty() || right.is_empty() {
        return extract_between(text, left, right).into_iter().collect();
    }
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(l_idx) = rest.find(left) {
        let after_left = &rest[l_idx + left.len()..];
        let Some(r_idx) = after_left.find(right) else {
            break;
        };
        out.push(after_left[..r_idx].to_string());
        rest = &after_left[r_idx + right.len()..];
    }
    out
}

#[derive(Debug)]
enum JsonToken {
    Key(String),
    RecursiveKey(String),
    Index(isize),
    Slice(Option<isize>, Option<isize>),
    Wildcard,
}

fn parse_json_path(path: &str) -> Result<Vec<JsonToken>, String> {
    let mut s = path.trim();
    if let Some(rest) = s.strip_prefix('$') {
        s = rest;
    }
    let mut tokens = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'.' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'.' {
                i += 2;
                let key = if i < bytes.len() && bytes[i] == b'[' {
                    i += 1;
                    let start = i;
                    let mut quote: Option<u8> = None;
                    while i < bytes.len() {
                        let b = bytes[i];
                        if let Some(q) = quote {
                            if b == q {
                                quote = None;
                            }
                        } else if b == b'\'' || b == b'"' {
                            quote = Some(b);
                        } else if b == b']' {
                            break;
                        }
                        i += 1;
                    }
                    if i >= bytes.len() || bytes[i] != b']' {
                        return Err(format!("Unclosed '[' after '..' in json_path '{path}'"));
                    }
                    let raw = s[start..i].trim();
                    i += 1;
                    unquote_literal(raw).unwrap_or_else(|| raw.to_string())
                } else {
                    let start = i;
                    while i < bytes.len() && bytes[i] != b'.' && bytes[i] != b'[' {
                        i += 1;
                    }
                    s[start..i].trim().to_string()
                };
                if key.is_empty() {
                    return Err(format!("Empty key after '..' in json_path '{path}'"));
                }
                tokens.push(JsonToken::RecursiveKey(key));
                continue;
            }
            i += 1;
            continue;
        }
        if bytes[i] == b'[' {
            i += 1;
            let start = i;
            let mut quote: Option<u8> = None;
            while i < bytes.len() {
                let b = bytes[i];
                if let Some(q) = quote {
                    if b == q {
                        quote = None;
                    }
                } else if b == b'\'' || b == b'"' {
                    quote = Some(b);
                } else if b == b']' {
                    break;
                }
                i += 1;
            }
            if i >= bytes.len() || bytes[i] != b']' {
                return Err(format!("Unclosed '[' in json_path '{path}'"));
            }
            let inner = s[start..i].trim();
            i += 1; // consume ']'
            if inner == "*" {
                tokens.push(JsonToken::Wildcard);
            } else if let Some(unq) = unquote_literal(inner) {
                tokens.push(JsonToken::Key(unq));
            } else if let Some((a, b)) = inner.split_once(':') {
                let s_idx = if a.trim().is_empty() {
                    None
                } else {
                    Some(
                        a.trim()
                            .parse::<isize>()
                            .map_err(|_| format!("Invalid slice start '{a}' in json_path '{path}'"))?,
                    )
                };
                let e_idx = if b.trim().is_empty() {
                    None
                } else {
                    Some(
                        b.trim()
                            .parse::<isize>()
                            .map_err(|_| format!("Invalid slice end '{b}' in json_path '{path}'"))?,
                    )
                };
                tokens.push(JsonToken::Slice(s_idx, e_idx));
            } else if let Ok(idx) = inner.parse::<isize>() {
                tokens.push(JsonToken::Index(idx));
            } else {
                tokens.push(JsonToken::Key(inner.to_string()));
            }
        } else {
            let start = i;
            while i < bytes.len() && bytes[i] != b'.' && bytes[i] != b'[' {
                i += 1;
            }
            let seg = s[start..i].trim();
            if seg == "*" {
                tokens.push(JsonToken::Wildcard);
            } else if !seg.is_empty() {
                tokens.push(JsonToken::Key(seg.to_string()));
            }
        }
    }
    Ok(tokens)
}

fn collect_recursive_key(val: &Value, key: &str, rest: &[JsonToken], out: &mut Vec<Value>) {
    match val {
        Value::Object(map) => {
            if let Some(target) = map.get(key) {
                if let Some(sub) = eval_json_tokens(target, rest) {
                    out.push(sub);
                }
            }
            for child in map.values() {
                collect_recursive_key(child, key, rest, out);
            }
        }
        Value::Array(arr) => {
            for item in arr {
                collect_recursive_key(item, key, rest, out);
            }
        }
        _ => {}
    }
}

fn resolve_slice_bound(bound: Option<isize>, len: usize, default_val: usize) -> usize {
    match bound {
        None => default_val,
        Some(v) if v < 0 => len.saturating_sub((-v) as usize),
        Some(v) => (v as usize).min(len),
    }
}

fn eval_json_tokens(val: &Value, tokens: &[JsonToken]) -> Option<Value> {
    if tokens.is_empty() {
        return Some(val.clone());
    }
    let (first, rest) = (&tokens[0], &tokens[1..]);
    match first {
        JsonToken::Key(k) => match val {
            Value::Object(map) => eval_json_tokens(map.get(k)?, rest),
            Value::Array(arr) => {
                let idx = k.parse::<isize>().ok()?;
                let resolved = if idx < 0 {
                    arr.len().checked_sub((-idx) as usize)?
                } else {
                    idx as usize
                };
                eval_json_tokens(arr.get(resolved)?, rest)
            }
            _ => None,
        },
        JsonToken::RecursiveKey(k) => {
            let mut collected = Vec::new();
            collect_recursive_key(val, k, rest, &mut collected);
            Some(Value::Array(collected))
        }
        JsonToken::Index(idx) => {
            let Value::Array(arr) = val else {
                return None;
            };
            let resolved = if *idx < 0 {
                arr.len().checked_sub((-*idx) as usize)?
            } else {
                *idx as usize
            };
            eval_json_tokens(arr.get(resolved)?, rest)
        }
        JsonToken::Slice(start_opt, end_opt) => {
            let Value::Array(arr) = val else {
                return None;
            };
            let len = arr.len();
            let s = resolve_slice_bound(*start_opt, len, 0);
            let e = resolve_slice_bound(*end_opt, len, len);
            if s >= e {
                return Some(Value::Array(Vec::new()));
            }
            if rest.is_empty() {
                return Some(Value::Array(arr[s..e].to_vec()));
            }
            let mut collected = Vec::with_capacity(e - s);
            for item in &arr[s..e] {
                if let Some(sub) = eval_json_tokens(item, rest) {
                    collected.push(sub);
                }
            }
            Some(Value::Array(collected))
        }
        JsonToken::Wildcard => match val {
            Value::Array(arr) => {
                let mut collected = Vec::with_capacity(arr.len());
                for item in arr {
                    if let Some(sub) = eval_json_tokens(item, rest) {
                        collected.push(sub);
                    }
                }
                Some(Value::Array(collected))
            }
            Value::Object(map) => {
                let mut collected = Vec::with_capacity(map.len());
                for item in map.values() {
                    if let Some(sub) = eval_json_tokens(item, rest) {
                        collected.push(sub);
                    }
                }
                Some(Value::Array(collected))
            }
            _ => None,
        },
    }
}

fn json_value_to_py(py: Python<'_>, val: &Value) -> PyResult<Py<PyAny>> {
    match val {
        Value::Null => Ok(py.None()),
        Value::Bool(b) => Ok(b.into_pyobject(py)?.to_owned().into_any().unbind()),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_pyobject(py)?.into_any().unbind())
            } else if let Some(u) = n.as_u64() {
                Ok(u.into_pyobject(py)?.into_any().unbind())
            } else if let Some(f) = n.as_f64() {
                Ok(f.into_pyobject(py)?.into_any().unbind())
            } else {
                Ok(py.None())
            }
        }
        Value::String(s) => Ok(s.into_pyobject(py)?.into_any().unbind()),
        Value::Array(arr) => {
            let list = PyList::empty(py);
            for item in arr {
                list.append(json_value_to_py(py, item)?)?;
            }
            Ok(list.into_any().unbind())
        }
        Value::Object(map) => {
            let dict = PyDict::new(py);
            for (k, v) in map {
                dict.set_item(k, json_value_to_py(py, v)?)?;
            }
            Ok(dict.into_any().unbind())
        }
    }
}

#[pyfunction]
pub fn extract_json_path(py: Python<'_>, text: &str, path: &str) -> PyResult<(bool, Py<PyAny>)> {
    let tokens = parse_json_path(path).map_err(PyValueError::new_err)?;
    let root: Value = serde_json::from_str(text)
        .map_err(|e| PyValueError::new_err(format!("Invalid JSON payload: {e}")))?;
    match eval_json_tokens(&root, &tokens) {
        Some(v) => Ok((true, json_value_to_py(py, &v)?)),
        None => Ok((false, py.None())),
    }
}

// ---------------------------------------------------------------------------
// PyO3 Classes: HtmlDocument & Element (Send + Sync via Mutex confinement)
// ---------------------------------------------------------------------------
#[pyclass(name = "HtmlDocument")]
pub struct NativeDocument {
    doc: SharedDoc,
}

#[pyfunction]
pub fn parse_html(html: &str) -> NativeDocument {
    NativeDocument {
        doc: Arc::new(Mutex::new(SendDoc(Document::from(html)))),
    }
}

#[pymethods]
impl NativeDocument {
    #[new]
    pub fn new(html: &str) -> Self {
        parse_html(html)
    }

    pub fn css<'py>(&self, py: Python<'py>, selector: &str) -> PyResult<Vec<Py<PyAny>>> {
        let guard = self.doc.lock().unwrap_or_else(|e| e.into_inner());
        let root_sel = Selection::from(guard.0.tree.root());
        run_css_on_selection(py, &self.doc, root_sel, selector, false)
    }

    #[pyo3(signature = (selector, default = None))]
    pub fn css_first<'py>(
        &self,
        py: Python<'py>,
        selector: &str,
        default: Option<Py<PyAny>>,
    ) -> PyResult<Option<Py<PyAny>>> {
        let guard = self.doc.lock().unwrap_or_else(|e| e.into_inner());
        let root_sel = Selection::from(guard.0.tree.root());
        Ok(run_css_on_selection(py, &self.doc, root_sel, selector, true)?
            .into_iter()
            .next()
            .or(default))
    }

    pub fn select<'py>(&self, py: Python<'py>, selector: &str) -> PyResult<Vec<Py<PyAny>>> {
        self.css(py, selector)
    }

    #[pyo3(signature = (selector, default = None))]
    pub fn select_one<'py>(
        &self,
        py: Python<'py>,
        selector: &str,
        default: Option<Py<PyAny>>,
    ) -> PyResult<Option<Py<PyAny>>> {
        self.css_first(py, selector, default)
    }

    pub fn xpath<'py>(&self, py: Python<'py>, expr: &str) -> PyResult<Vec<Py<PyAny>>> {
        eval_xpath(py, &self.doc, None, expr, false)
    }

    #[pyo3(signature = (expr, default = None))]
    pub fn xpath_first<'py>(
        &self,
        py: Python<'py>,
        expr: &str,
        default: Option<Py<PyAny>>,
    ) -> PyResult<Option<Py<PyAny>>> {
        Ok(eval_xpath(py, &self.doc, None, expr, true)?
            .into_iter()
            .next()
            .or(default))
    }

    #[pyo3(signature = (query, default = None))]
    pub fn find<'py>(
        &self,
        py: Python<'py>,
        query: &str,
        default: Option<Py<PyAny>>,
    ) -> PyResult<Option<Py<PyAny>>> {
        let q = query.trim();
        if is_xpath_query(q) {
            self.xpath_first(py, q, default)
        } else {
            self.css_first(py, q, default)
        }
    }

    pub fn find_all<'py>(&self, py: Python<'py>, query: &str) -> PyResult<Vec<Py<PyAny>>> {
        let q = query.trim();
        if is_xpath_query(q) {
            self.xpath(py, q)
        } else {
            self.css(py, q)
        }
    }

    #[pyo3(name = "get_text", signature = (separator = " ", strip = true))]
    pub fn doc_get_text(&self, separator: &str, strip: bool) -> String {
        let guard = self.doc.lock().unwrap_or_else(|e| e.into_inner());
        let root = guard.0.tree.root();
        let parts: Vec<String> = all_text_descendants(&root)
            .into_iter()
            .filter_map(|s| {
                if strip {
                    let t = s.trim();
                    if t.is_empty() {
                        None
                    } else {
                        Some(t.to_string())
                    }
                } else {
                    Some(s)
                }
            })
            .collect();
        parts.join(separator)
    }

    #[getter(text)]
    pub fn prop_text(&self) -> String {
        let guard = self.doc.lock().unwrap_or_else(|e| e.into_inner());
        guard.0.text().to_string()
    }

    #[getter]
    pub fn html(&self) -> String {
        let guard = self.doc.lock().unwrap_or_else(|e| e.into_inner());
        guard.0.html().to_string()
    }

    pub fn __repr__(&self) -> String {
        "<HtmlDocument>".to_string()
    }
}

#[pyclass(name = "Element")]
pub struct NativeElement {
    doc: SharedDoc,
    id: NodeId,
}

#[pymethods]
impl NativeElement {
    #[getter]
    pub fn tag(&self) -> String {
        let guard = self.doc.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .0
            .tree
            .get(&self.id)
            .and_then(|n| n.node_name())
            .map(|s| s.to_string().to_ascii_lowercase())
            .unwrap_or_default()
    }

    #[getter(text)]
    pub fn prop_text(&self) -> String {
        let guard = self.doc.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .0
            .tree
            .get(&self.id)
            .map(|n| n.text().to_string())
            .unwrap_or_default()
    }

    #[getter]
    pub fn own_text(&self) -> String {
        let guard = self.doc.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .0
            .tree
            .get(&self.id)
            .map(|n| direct_text_children(&n).join(""))
            .unwrap_or_default()
    }

    #[pyo3(name = "get_text", signature = (separator = " ", strip = true))]
    pub fn elem_get_text(&self, separator: &str, strip: bool) -> String {
        let guard = self.doc.lock().unwrap_or_else(|e| e.into_inner());
        let Some(node) = guard.0.tree.get(&self.id) else {
            return String::new();
        };
        let parts: Vec<String> = all_text_descendants(&node)
            .into_iter()
            .filter_map(|s| {
                if strip {
                    let t = s.trim();
                    if t.is_empty() {
                        None
                    } else {
                        Some(t.to_string())
                    }
                } else {
                    Some(s)
                }
            })
            .collect();
        parts.join(separator)
    }

    #[getter]
    pub fn html(&self) -> String {
        let guard = self.doc.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .0
            .tree
            .get(&self.id)
            .map(|n| n.inner_html().to_string())
            .unwrap_or_default()
    }

    #[getter]
    pub fn outer_html(&self) -> String {
        let guard = self.doc.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .0
            .tree
            .get(&self.id)
            .map(|n| n.html().to_string())
            .unwrap_or_default()
    }

    #[getter]
    pub fn attrs(&self) -> HashMap<String, String> {
        let guard = self.doc.lock().unwrap_or_else(|e| e.into_inner());
        let mut map = HashMap::new();
        if let Some(n) = guard.0.tree.get(&self.id) {
            for attr in n.attrs() {
                map.insert(attr.name.local.to_string(), attr.value.to_string());
            }
        }
        map
    }

    #[getter]
    pub fn attrib(&self) -> HashMap<String, String> {
        self.attrs()
    }

    #[pyo3(signature = (name, default = None))]
    pub fn attr(&self, name: &str, default: Option<String>) -> Option<String> {
        let guard = self.doc.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .0
            .tree
            .get(&self.id)
            .and_then(|n| n.attr(name))
            .map(|v| v.to_string())
            .or(default)
    }

    #[getter]
    pub fn parent(&self) -> Option<NativeElement> {
        let guard = self.doc.lock().unwrap_or_else(|e| e.into_inner());
        let node = guard.0.tree.get(&self.id)?;
        let p = node.parent()?;
        if p.is_element() {
            Some(NativeElement {
                doc: Arc::clone(&self.doc),
                id: p.id,
            })
        } else {
            None
        }
    }

    #[getter]
    pub fn children(&self) -> Vec<NativeElement> {
        let guard = self.doc.lock().unwrap_or_else(|e| e.into_inner());
        let Some(node) = guard.0.tree.get(&self.id) else {
            return Vec::new();
        };
        node.children()
            .into_iter()
            .filter(|c| c.is_element())
            .map(|c| NativeElement {
                doc: Arc::clone(&self.doc),
                id: c.id,
            })
            .collect()
    }

    #[getter]
    pub fn next_sibling(&self) -> Option<NativeElement> {
        let guard = self.doc.lock().unwrap_or_else(|e| e.into_inner());
        let mut cur = guard.0.tree.get(&self.id)?.next_sibling();
        while let Some(sib) = cur {
            if sib.is_element() {
                return Some(NativeElement {
                    doc: Arc::clone(&self.doc),
                    id: sib.id,
                });
            }
            cur = sib.next_sibling();
        }
        None
    }

    #[getter]
    pub fn prev_sibling(&self) -> Option<NativeElement> {
        let guard = self.doc.lock().unwrap_or_else(|e| e.into_inner());
        let mut cur = guard.0.tree.get(&self.id)?.prev_sibling();
        while let Some(sib) = cur {
            if sib.is_element() {
                return Some(NativeElement {
                    doc: Arc::clone(&self.doc),
                    id: sib.id,
                });
            }
            cur = sib.prev_sibling();
        }
        None
    }

    #[getter]
    pub fn ancestors(&self) -> Vec<NativeElement> {
        let guard = self.doc.lock().unwrap_or_else(|e| e.into_inner());
        let Some(node) = guard.0.tree.get(&self.id) else {
            return Vec::new();
        };
        node.ancestors(None)
            .into_iter()
            .filter(|a| a.is_element())
            .map(|a| NativeElement {
                doc: Arc::clone(&self.doc),
                id: a.id,
            })
            .collect()
    }

    pub fn css<'py>(&self, py: Python<'py>, selector: &str) -> PyResult<Vec<Py<PyAny>>> {
        let guard = self.doc.lock().unwrap_or_else(|e| e.into_inner());
        let Some(node) = guard.0.tree.get(&self.id) else {
            return Ok(Vec::new());
        };
        run_css_on_selection(py, &self.doc, Selection::from(node), selector, false)
    }

    #[pyo3(signature = (selector, default = None))]
    pub fn css_first<'py>(
        &self,
        py: Python<'py>,
        selector: &str,
        default: Option<Py<PyAny>>,
    ) -> PyResult<Option<Py<PyAny>>> {
        let guard = self.doc.lock().unwrap_or_else(|e| e.into_inner());
        let Some(node) = guard.0.tree.get(&self.id) else {
            return Ok(default);
        };
        Ok(
            run_css_on_selection(py, &self.doc, Selection::from(node), selector, true)?
                .into_iter()
                .next()
                .or(default),
        )
    }

    pub fn select<'py>(&self, py: Python<'py>, selector: &str) -> PyResult<Vec<Py<PyAny>>> {
        self.css(py, selector)
    }

    #[pyo3(signature = (selector, default = None))]
    pub fn select_one<'py>(
        &self,
        py: Python<'py>,
        selector: &str,
        default: Option<Py<PyAny>>,
    ) -> PyResult<Option<Py<PyAny>>> {
        self.css_first(py, selector, default)
    }

    pub fn xpath<'py>(&self, py: Python<'py>, expr: &str) -> PyResult<Vec<Py<PyAny>>> {
        eval_xpath(py, &self.doc, Some(self.id), expr, false)
    }

    #[pyo3(signature = (expr, default = None))]
    pub fn xpath_first<'py>(
        &self,
        py: Python<'py>,
        expr: &str,
        default: Option<Py<PyAny>>,
    ) -> PyResult<Option<Py<PyAny>>> {
        Ok(eval_xpath(py, &self.doc, Some(self.id), expr, true)?
            .into_iter()
            .next()
            .or(default))
    }

    #[pyo3(signature = (query, default = None))]
    pub fn find<'py>(
        &self,
        py: Python<'py>,
        query: &str,
        default: Option<Py<PyAny>>,
    ) -> PyResult<Option<Py<PyAny>>> {
        let q = query.trim();
        if is_xpath_query(q) {
            self.xpath_first(py, q, default)
        } else {
            self.css_first(py, q, default)
        }
    }

    pub fn find_all<'py>(&self, py: Python<'py>, query: &str) -> PyResult<Vec<Py<PyAny>>> {
        let q = query.trim();
        if is_xpath_query(q) {
            self.xpath(py, q)
        } else {
            self.css(py, q)
        }
    }

    pub fn re(&self, pattern: &str) -> PyResult<Vec<String>> {
        extract_re(&self.prop_text(), pattern)
    }

    #[pyo3(signature = (pattern, default = None))]
    pub fn re_first(&self, pattern: &str, default: Option<String>) -> PyResult<Option<String>> {
        Ok(extract_re_first(&self.prop_text(), pattern)?.or(default))
    }

    #[pyo3(signature = (left, right, default = None))]
    pub fn between(&self, left: &str, right: &str, default: Option<String>) -> Option<String> {
        extract_between(&self.prop_text(), left, right).or(default)
    }

    pub fn between_all(&self, left: &str, right: &str) -> Vec<String> {
        extract_between_all(&self.prop_text(), left, right)
    }

    pub fn __getitem__(&self, key: &str) -> PyResult<String> {
        self.attr(key, None)
            .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err(key.to_string()))
    }

    pub fn __contains__(&self, key: &str) -> bool {
        let guard = self.doc.lock().unwrap_or_else(|e| e.into_inner());
        guard.0.tree.get(&self.id).and_then(|n| n.attr(key)).is_some()
    }

    pub fn __str__(&self) -> String {
        self.prop_text()
    }

    pub fn __repr__(&self) -> String {
        let tag = self.tag();
        let id_attr = self
            .attr("id", None)
            .map(|v| format!(" id=\"{v}\""))
            .unwrap_or_default();
        let cls_attr = self
            .attr("class", None)
            .map(|v| format!(" class=\"{v}\""))
            .unwrap_or_default();
        format!("<Element <{tag}{id_attr}{cls_attr}>>")
    }
}

const XPATH_AXES: &[&str] = &[
    "child::",
    "descendant::",
    "descendant-or-self::",
    "parent::",
    "ancestor::",
    "ancestor-or-self::",
    "following-sibling::",
    "preceding-sibling::",
    "following::",
    "preceding::",
    "self::",
    "attribute::",
];

pub fn is_xpath_query(q: &str) -> bool {
    q.starts_with('/')
        || q.starts_with("./")
        || q.starts_with("../")
        || q.starts_with('(')
        || q.starts_with('@')
        || XPATH_AXES.iter().any(|axis| q.contains(axis))
}
