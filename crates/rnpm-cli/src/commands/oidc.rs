//! npm's optional CI identity exchange. Failure falls back to configured credentials.
use reqwest::Url;

pub(crate) async fn exchange(registry: &Url, package: &str) -> Option<String> {
    let github = std::env::var("GITHUB_ACTIONS").is_ok_and(|v| v == "true");
    let gitlab = std::env::var_os("GITLAB_CI").is_some();
    let circle = std::env::var_os("CIRCLECI").is_some();
    if !github && !gitlab && !circle { return None; }
    let client = reqwest::Client::new();
    let mut identity = std::env::var("NPM_ID_TOKEN").ok().filter(|s| !s.is_empty());
    if identity.is_none() && github {
        let mut url = Url::parse(&std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL").ok()?).ok()?;
        url.query_pairs_mut().append_pair("audience", &format!("npm:{}", registry.host_str()?));
        let response = client.get(url).header("accept", "application/json")
            .bearer_auth(std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").ok()?)
            .send().await.ok()?.error_for_status().ok()?;
        let body: serde_json::Value = response.json().await.ok()?;
        identity = body["value"].as_str().filter(|s| !s.is_empty()).map(str::to_string);
    }
    let url = registry.join(&format!("/-/npm/v1/oidc/token/exchange/package/{}", rnpm_config::encode_package_name(package))).ok()?;
    let response = client.post(url).bearer_auth(identity?).send().await.ok()?.error_for_status().ok()?;
    let body: serde_json::Value = response.json().await.ok()?;
    body["token"].as_str().filter(|s| !s.is_empty()).map(str::to_string)
}
