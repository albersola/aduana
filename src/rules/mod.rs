//! Parser, validator, evaluator and formatter for Aduana rules.

mod ast;
mod eval;
mod format;
mod parser;
mod path;

pub use ast::{
    AllowRule, AllowedMatch, Client, ClientAddr, ConnectDecision, Decision, DenyReason,
    EvalRequest, FromMatcher, HostPattern, HttpMethod, MethodMatcher, ParseError, PathPattern,
    PathSegment, Policy, ResolvedTransform, Rule, Scheme, Span, Target, TemplatePart, Transform,
    ValueTemplate,
};
pub use eval::apply_transforms;
pub use format::{format_client, format_policy, format_rule};
pub use parser::{PROTECTED_HEADERS, is_protected_header, parse_rules};
pub use path::{PathError, validate_request_path};
