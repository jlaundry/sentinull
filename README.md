# Sentinull

Sentinull is a local emulator for Azure Log Analytics' Log Ingestion API, to be used for integration testing.

And because it sends logs to `/dev/null`, it's also the ultimate web-scale solution for Sentinel logs!

## Usage

Sentinull implements the [Upload](https://learn.microsoft.com/en-us/rest/api/ingestion/upload/upload?view=rest-ingestion-2023-01-01&tabs=HTTP) API endpoint, aka `/dataCollectionRules/{ruleID}/streams/{stream}?api-version=2023-01-01`, following the Microsoft documentation as closely as possible.

Requests should consist of a JSON-encoded POST body, and use the following headers:

| Header                 | Required? | Description                                                                                                         |
|------------------------|-----------|---------------------------------------------------------------------------------------------------------------------|
| Authorization          | Yes       | Bearer token. The token signature and `iss` are NOT validated, only the `nbf`, `exp`, and `aud` claims are checked. |
| Content-Type           | Yes       | Always application/json                                                                                             |
| Content-Encoding       | No        | Optionally gzip compressed                                                                                          |
| x-ms-client-request-id | No        | String-formatted GUID                                                                                               |

To help testing various scenarios, the Data Collection Rule ID can be one of:

  * `dcr-accepted` which will accept all valid JSON with no schema checks.
  * `dcr-validated` will accept valid JSON; and validate the keys, and value data types against the expected schema (see below)
  * `dcr-forbidden` will always result in a 403 Forbidden response, as if the user/principal had not been assigned the Monitoring Metrics Publisher role on the Data Collection Rule

Other Rule IDs result in 404 Not Found responses.

When using `dcr-validated`, following Streams can be used:

  * `Custom-*` schemas are not validated
  * `Microsoft-Syslog` requests are validated against the [Syslog](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/syslog) table schema, and invalid columns or data will result in a 400 Bad Request

Apart from JSON and Schema validation, the following validation is performed:

  * Requests adhere to the [1MB maximum size](https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/service-limits#logs-ingestion-api) (for either compressed or uncompressed data) - if you submit more than 1MB, you should get a 413 Request Too Large response

Sentinull includes a few optional feature flags:

  * `--jwt-audience {aud}` by default, the Bearer JWT aud is expected to be `https://monitor.azure.com/.default` - you may want to change this to mock a regional cloud.
  * `--listen {address}` defaults to `localhost:8564`

## References

  * https://learn.microsoft.com/en-us/rest/api/ingestion/upload/upload?view=rest-ingestion-2023-01-01&tabs=HTTP
  * https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview
  * https://learn.microsoft.com/en-us/azure/azure-monitor/logs/tutorial-logs-ingestion-api?tabs=dcr
  * https://learn.microsoft.com/en-us/azure/azure-monitor/logs/tutorial-logs-ingestion-code?tabs=net#troubleshooting
  * https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/service-limits#logs-ingestion-api
