use axum::response::IntoResponse;

pub(crate) async fn signin_handler() -> impl IntoResponse {
    "signin handler".into_response()
}

pub(crate) async fn signup_handler() -> impl IntoResponse {
    "signup handler".into_response()
}
