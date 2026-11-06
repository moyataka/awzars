use crate::error::{AwzarsError, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use chromiumoxide::cdp::browser_protocol::{fetch, network};
use chromiumoxide::page::Page;
use futures::StreamExt;
use std::time::Duration;
use zeroize::Zeroizing;

const SIGNIN_HOSTS: &[&str] = &[
    "signin.aws.amazon.com",
    "signin.amazonaws.cn",
    "signin.amazonaws-us-gov.com",
];

async fn next_saml_request<Requests, ContinueFuture>(
    requests: &mut Requests,
    mut continue_request: impl FnMut(fetch::RequestId) -> ContinueFuture,
) -> Result<std::sync::Arc<fetch::EventRequestPaused>>
where
    Requests: futures::Stream<Item = std::sync::Arc<fetch::EventRequestPaused>> + Unpin,
    ContinueFuture: std::future::Future<Output = Result<()>>,
{
    while let Some(event) = requests.next().await {
        if is_saml_post(&event.request.method, &event.request.url) {
            return Ok(event);
        }
        if continue_request(event.request_id.clone()).await.is_err() {
            tracing::debug!("Could not resume a non-SAML request; continuing to wait for sign-in");
        }
    }
    Err(AwzarsError::Browser("SAML request listener closed".into()))
}

fn is_saml_post(method: &str, destination: &str) -> bool {
    let Ok(destination) = url::Url::parse(destination) else {
        return false;
    };
    method == "POST"
        && destination.scheme() == "https"
        && destination.username().is_empty()
        && destination.password().is_none()
        && destination.port_or_known_default() == Some(443)
        && destination.path() == "/saml"
        && destination.host_str().is_some_and(|host| {
            SIGNIN_HOSTS
                .iter()
                .any(|allowed| host == *allowed || host.ends_with(&format!(".{allowed}")))
        })
}

fn response_from_form(body: &str) -> Result<Zeroizing<String>> {
    // Includes the URL-encoding overhead for the parser's 256 KiB XML limit.
    if body.len() > 1024 * 1024 {
        return Err(AwzarsError::Saml("SAML form is too large".into()));
    }
    let mut responses = url::form_urlencoded::parse(body.as_bytes())
        .filter(|(name, _)| name == "SAMLResponse")
        .map(|(_, value)| Zeroizing::new(value.into_owned()));
    match (responses.next(), responses.next()) {
        (Some(response), None) if !response.is_empty() => Ok(response),
        _ => Err(AwzarsError::Saml(
            "Expected one nonempty SAMLResponse in the sign-in POST".into(),
        )),
    }
}

fn body_from_entries(entries: &[network::PostDataEntry]) -> Result<Zeroizing<String>> {
    let body = entries
        .iter()
        .try_fold(Zeroizing::new(Vec::new()), |mut body, entry| {
            let encoded = entry
                .bytes
                .as_ref()
                .ok_or_else(|| AwzarsError::Saml("Missing SAML request body entry".into()))?;
            let encoded: &str = encoded.as_ref();
            if encoded.len() > 2 * 1024 * 1024 || body.len() > 1024 * 1024 {
                return Err(AwzarsError::Saml("SAML form is too large".into()));
            }
            STANDARD
                .decode_vec(encoded, &mut body)
                .map_err(|_| AwzarsError::Saml("Invalid SAML request body encoding".into()))?;
            Ok(body)
        })?;
    std::str::from_utf8(&body)
        .map(|body| Zeroizing::new(body.to_string()))
        .map_err(|_| AwzarsError::Saml("SAML request body is not UTF-8".into()))
}

pub(super) async fn capture(
    page: &Page,
    login_url: &str,
    timeout: Duration,
) -> Result<Zeroizing<String>> {
    let mut requests = page
        .event_listener::<fetch::EventRequestPaused>()
        .await
        .map_err(|_| AwzarsError::Browser("Unable to listen for SAML requests".into()))?;
    let patterns = SIGNIN_HOSTS
        .iter()
        .flat_map(|host| [format!("https://{host}/*"), format!("https://*.{host}/*")])
        .map(|pattern| {
            fetch::RequestPattern::builder()
                .url_pattern(pattern)
                .build()
        });
    page.execute(fetch::EnableParams::builder().patterns(patterns).build())
        .await
        .map_err(|_| AwzarsError::Browser("Unable to enable SAML interception".into()))?;

    let capture = async {
        let event = next_saml_request(&mut requests, |identifier| async move {
            page.execute(fetch::ContinueRequestParams::new(identifier))
                .await
                .map(|_| ())
                .map_err(|_| AwzarsError::Browser("Unable to continue sign-in request".into()))
        })
        .await?;

        let body = match &event.request.post_data_entries {
            Some(entries) if !entries.is_empty() => body_from_entries(entries),
            _ => match &event.network_id {
                Some(identifier) => page
                    .execute(network::GetRequestPostDataParams::new(identifier.clone()))
                    .await
                    .map(|response| Zeroizing::new(response.result.post_data))
                    .map_err(|_| AwzarsError::Saml("Unable to read SAML request body".into())),
                None => Err(AwzarsError::Saml("Missing SAML request body".into())),
            },
        };
        // Abort even malformed assertions: the console must not consume the POST.
        page.execute(fetch::FailRequestParams::new(
            event.request_id.clone(),
            network::ErrorReason::Aborted,
        ))
        .await
        .map_err(|_| AwzarsError::Browser("Unable to stop SAML console submission".into()))?;
        response_from_form(&body?)
    };

    // Navigation and capture must run together: an immediate auto-submit can
    // pause the first navigation before Page.goto resolves.
    let navigation = async {
        if let Err(error) = page.goto(login_url).await {
            if !error.to_string().contains("net::ERR_ABORTED") {
                return Err(AwzarsError::Browser(
                    "Failed to navigate to Azure login".into(),
                ));
            }
        }
        std::future::pending::<Result<Zeroizing<String>>>().await
    };
    let result = tokio::time::timeout(timeout, async {
        tokio::select! {
            biased;
            response = capture => response,
            error = navigation => error,
        }
    })
    .await
    .unwrap_or_else(|_| Err(AwzarsError::Browser("Authentication timed out".into())));

    if result.is_err() {
        let _ = page
            .execute(chromiumoxide::cdp::browser_protocol::page::StopLoadingParams::default())
            .await;
    }
    if page.execute(fetch::DisableParams::default()).await.is_err() {
        tracing::debug!("Unable to disable SAML interception on the closing page");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancelled_non_saml_request_does_not_end_capture() {
        let event = |identifier: &str, method: &str| {
            std::sync::Arc::new(
                serde_json::from_value::<fetch::EventRequestPaused>(serde_json::json!({
                    "requestId": identifier, "frameId": "frame", "resourceType": "Document",
                    "request": {
                        "url": "https://signin.aws.amazon.com/saml", "method": method,
                        "headers": {}, "initialPriority": "High", "referrerPolicy": "no-referrer"
                    }
                }))
                .unwrap(),
            )
        };
        let assertion = event("assertion", "POST");
        let mut requests = futures::stream::iter([
            event("cancelled", "GET"),
            event("continued", "GET"),
            assertion.clone(),
        ]);
        let mut continued = Vec::new();
        let captured = next_saml_request(&mut requests, |identifier| {
            continued.push(identifier.as_ref().to_string());
            std::future::ready(if identifier.as_ref() == "cancelled" {
                Err(AwzarsError::Browser("Invalid InterceptionId".into()))
            } else {
                Ok(())
            })
        })
        .await
        .unwrap();
        assert_eq!(continued, ["cancelled", "continued"]);
        assert!(std::sync::Arc::ptr_eq(&captured, &assertion));
        assert!(
            next_saml_request(&mut requests, |_| std::future::ready(Ok(())))
                .await
                .is_err()
        );
    }

    #[test]
    fn capture_accepts_only_aws_https_saml_posts() {
        for host in SIGNIN_HOSTS {
            for host in [host.to_string(), format!("us-east-1.{host}")] {
                assert!(is_saml_post("POST", &format!("https://{host}/saml")));
            }
        }
        for destination in [
            "http://signin.aws.amazon.com/saml",
            "https://signin.aws.amazon.com.evil.test/saml",
            "https://evilsignin.aws.amazon.com/saml",
            "https://console.aws.amazon.com/saml",
            "https://login.microsoftonline.com/saml",
            "https://signin.aws.amazon.com:444/saml",
            "https://user@signin.aws.amazon.com/saml",
            "https://signin.aws.amazon.com/other",
        ] {
            assert!(!is_saml_post("POST", destination), "{destination}");
        }
        assert!(!is_saml_post("GET", "https://signin.aws.amazon.com/saml"));
    }

    #[test]
    fn extracts_assertion_from_post_without_an_aws_document() {
        let encoded_assertion = "abc+/==";
        let form = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("RelayState", "https://console.aws.amazon.com/")
            .append_pair("SAMLResponse", encoded_assertion)
            .finish();
        assert_eq!(&*response_from_form(&form).unwrap(), encoded_assertion);
        let entries: Vec<_> = form
            .as_bytes()
            .chunks(11)
            .map(|chunk| {
                network::PostDataEntry::builder()
                    .bytes(STANDARD.encode(chunk))
                    .build()
            })
            .collect();
        let body = body_from_entries(&entries).unwrap();
        assert_eq!(&*response_from_form(&body).unwrap(), encoded_assertion);
    }

    #[test]
    fn rejects_missing_empty_duplicate_and_oversized_assertions() {
        for body in [
            "",
            "RelayState=x",
            "SAMLResponse=",
            "SAMLResponse=a&SAMLResponse=b",
        ] {
            assert!(response_from_form(body).is_err());
        }
        assert!(response_from_form(&"a".repeat(1024 * 1024 + 1)).is_err());
    }
}
