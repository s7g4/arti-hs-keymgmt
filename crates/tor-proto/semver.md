POSSIBLY-BREAKING: `StreamOps` trait now has a (defaulted) `new_handle` function
BREAKING: stream types used in `OutboundClientHandshake`, `UnverifiedChannel`, `VerifiedChannel` are required to implement `StreamOps`
BREAKING: `ConversationInHandler` now only has one lifetime parameter
BREAKING: `ConversationInHandler::send_message` is now `async`
