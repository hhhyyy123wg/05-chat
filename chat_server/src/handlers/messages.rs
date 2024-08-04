use axum::response::IntoResponse;

pub(crate) async fn send_message_handler() -> impl IntoResponse {
    "send_message_handler".to_string()
}

pub(crate) async fn list_message_handler() -> impl IntoResponse {
    "list_message_handler".to_string()
}
