# Themis rebuild connector for Jenkins (reference)

This program starts an image build in Jenkins when Themis asks for one. It is the reference
build connector of EDR-REBUILD-01 (decision D8, step R5).

Themis decides. This program builds. It owns no security decision, reads nothing from a Themis
database, and imports no Themis code. The contract between the two is one signed HTTP request
in and one HTTP status call out.

It is tested against a fake Jenkins and a fake Themis only. It has not yet run against a real
Jenkins (see "Limits").

## What it does

1. It receives `POST /events` with the event `themis.rebuild.requested.v1` from the
   Communication node of Themis.
2. It checks the signature of the body (`X-Themis-Signature: sha256=<hex HMAC-SHA256>`). A
   request with a missing or wrong signature gets `401` and nothing is stored.
3. It stores the request under the event id before it answers. The id is the intent id.
   The same id a second time returns the stored state and starts nothing (D12).
4. It checks the request (D18, D31). A request that fails a check is stored as `refused`.
5. It asks Jenkins for one build of the named job through the Jenkins API.
6. It tells Themis what became of the request: `submitted`, `refused` or `uncertain` (D28).

## The checks on a request

All of them are required. None can be switched off.

1. The event type is `themis.rebuild.requested.v1`.
2. The event is not older than `max_event_age` (default 24 hours).
3. The build profile names a job, and that job is on the allow-list for the Product and the
   Project of the event.
4. Every parameter of the build profile is in the schema of that job. An unknown parameter is
   refused, not dropped.
5. Every value passes the rule of its parameter. The rules:

   | Rule | Accepts |
   | --- | --- |
   | `branch` | a branch name: letters, digits, `.`, `_`, `-`, `/`; no `..`, no `//`, no leading `-` |
   | `image_tag` | an image tag: letters, digits, `.`, `_`, `-` |
   | `registry_path` | `host[:port]/path` in lower case |
   | `enum` | one of the listed `values` |
   | `bool` | `true` or `false` |
   | `int` | a whole number |
   | `text` | letters, digits, space and `_ . , : @ / + = -` |

   Each rule has a length limit (`max_len`, at most 1024). No rule lets shell or script syntax
   through. The tests try a list of such values against every rule.
6. A list or an object as a parameter value is refused.
7. A parameter whose name starts with `THEMIS_` is refused. The connector sets those itself.

Values travel to Jenkins as form parameters of the API call. No value is ever joined into a
command, a path or a query.

## What the Jenkins job receives

The parameters of the build profile, plus these, set by the connector from the signed event:

| Parameter | Meaning |
| --- | --- |
| `THEMIS_INTENT_ID` | the id of this request; the connector finds the build again by it |
| `THEMIS_PRODUCT_ID`, `THEMIS_PROJECT_ID`, `THEMIS_RELEASE_ID` | what is built |
| `THEMIS_PRIOR_SBOM_ID` | the SBOM the new build is compared with |
| `THEMIS_ATTEMPT` | the attempt number of the rebuild cycle |
| `THEMIS_TARGETED_CVES` | the CVE ids the rebuild aims at, sorted, comma separated |

The job must declare all seven as string parameters, or Jenkins drops them and the connector
cannot find the build after a restart.

The job itself uploads the new SBOM to Themis when the build is done. That is the normal
intake and not part of this connector.

## One request, at most one build

The connector keeps one record per request in `store_dir`. Its states (D37):

| State | Meaning |
| --- | --- |
| `received` | stored and checked; no call to Jenkins yet |
| `submitting` | one worker holds the claim and may be calling Jenkins |
| `submitted` | Jenkins accepted the build; this is what counts (D38) |
| `refused` | a check or Jenkins said no; no build |
| `uncertain` | the connector cannot tell whether a build was started; a person settles it in Themis |

Rules that keep it to one build (D39):

1. Only the worker that wins the claim calls Jenkins. The claim is one conditional write.
2. The call to Jenkins is shorter than the claim (`call_timeout` < `claim_ttl`).
3. A worker that lost its claim cannot write a result. Each claim has a counter and a result
   names it.
4. A record left in `submitting` (a crash, a cut connection) is never called again directly.
   The connector first asks Jenkins for a build that carries the intent id.
   Found: `submitted`. Not found, and the search was complete: back to `received` and one new
   call. Cannot tell: `uncertain`.
5. A recovery pass runs at start and every `recovery_interval`. It picks up every record that
   is not finished or not yet reported. No stored request is dropped in silence.

What "the search was complete" means for Jenkins: the connector reads the queue and the newest
100 builds of the job, twice, a few seconds apart. "Not found" is believed only when both
passes agree and the builds that were read reach back before the time the request arrived.
Otherwise the answer is `uncertain`.

## The credential, and why the connector may refuse to start

At start the connector asks Jenkins what the user can reach (D33). It starts only when:

1. Jenkins knows the user and the token.
2. Every job on the allow-list is visible to the user.
3. No other job is visible to the user.

Jenkins has no call for "the jobs this user may build". The connector uses the jobs the user
can see, which is the wider right, so the check is on the safe side. Folders deeper than six
levels fail the check.

Point 3 can be accepted on purpose with `"accept_broad_credential": true`. The connector then
says so in its log at every start and on `GET /status`. The allow-list still decides what is
started; only the second line of defence is weaker.

The check never starts a job to find out.

## Setting it up

### 1. Jenkins

1. Create a user for the connector, for example `themis-builder`.
2. Give it `Overall/Read`, and `Job/Read` and `Job/Build` on the allowed jobs only (project
   based matrix authorization, or a folder with its own permissions).
3. Create an API token for that user.
4. Make each allowed job a parameterized job with the seven `THEMIS_` parameters above and
   the parameters of its schema.

### 2. Themis

1. On the Communication node, route the request to the connector and sign it:

   ```sh
   # the audience name is free; "build-connector" is used here
   THEMIS_COMMUNICATION_REBUILD_OPEN_FROM=decision
   THEMIS_COMMUNICATION_WEBHOOK_ENABLED=1
   THEMIS_COMMUNICATION_WEBHOOK_TARGETS=build-connector=https://<connector-host>/events
   THEMIS_COMMUNICATION_WEBHOOK_SECRET_BUILD_CONNECTOR=<the signing secret>
   THEMIS_COMMUNICATION_WEBHOOK_ROUTES=rebuild_requested=build-connector
   ```

   Keep the targets and routes you already have; the pairs are separated by `;`.
2. Mint an API key with scope `delivery:callback` for the status call.
3. Store a build profile on the Project or the Release in Registry. Its shape for this
   connector is:

   ```json
   {"job": "team/build-image", "parameters": {"BRANCH": "release/1.2", "PUSH": true}}
   ```

   A build profile holds no secret (D10).

### 3. The connector

1. Build it: `go build -o themis-rebuild-connector .` in this directory. It needs only the Go
   standard library.
2. Copy `connector.example.json` and change it. Every field:

   | Field | Meaning |
   | --- | --- |
   | `listen` | address to serve on; default `127.0.0.1:8090` |
   | `store_dir` | directory of the stored records; must survive a restart |
   | `signing_secret_env` | NAME of the environment variable with the signing secret |
   | `themis.callback_url` | `https://<themis>/.../callbacks/ci-rebuild` on the Communication node |
   | `themis.api_key_env` | NAME of the variable with the `delivery:callback` key |
   | `jenkins.url`, `jenkins.user` | the Jenkins server and the connector's user |
   | `jenkins.token_env` | NAME of the variable with the API token |
   | `jenkins.accept_broad_credential` | the stated exception above; default `false` |
   | `max_event_age` | older events are refused; default `24h` |
   | `claim_ttl` | how long one worker holds a request; default `2m` |
   | `call_timeout` | bound of one call; must be shorter than `claim_ttl`; default `30s` |
   | `recovery_interval` | how often the recovery pass runs; default `30s` |
   | `retention` | how long a finished, reported record is kept; must be longer than `max_event_age`; default `720h` |
   | `tls_cert_file`, `tls_key_file` | serve https itself; set both or none |
   | `allow` | per Product and Project: the jobs that may be started |
   | `jobs` | per job: every parameter with its rule |

   Secrets are never in the file. The file names the environment variables that hold them.
   An unknown field is an error, so a mistyped allow-list is not read as an empty one.
   `callback_url` and `jenkins.url` must be https; http is taken for the loopback address only.
3. Check without starting: `themis-rebuild-connector -config connector.json -check`.
4. Run it: `themis-rebuild-connector -config connector.json`.
5. Themis sends a rebuild request to https only. Give the connector a certificate
   (`tls_cert_file`, `tls_key_file`) or put a TLS proxy in front of it.

### What you can ask it

| Call | Answer |
| --- | --- |
| `POST /events` | `202` stored (new or known), `401` bad signature, `400` not an event, `503` the store failed |
| `GET /healthz` | `200` |
| `GET /status` | how many records are in each state, how many are not reported yet, and whether the broad credential exception is on |

## Limits

1. Not yet run against a real Jenkins. The Jenkins answers it relies on (the `Location` of a
   queued build, the queue and build lists, `whoAmI`) are the documented ones, checked against
   a fake only.
2. The store is a directory of files with a file lock. Several instances may share it on one
   host, or on a file system whose locks work across hosts. Otherwise run one instance, or
   implement the `Store` interface on a database.
3. The credential check sees what the user can see, not what it can build.
4. A job with more than 100 builds between the request and the search gives `uncertain`
   instead of a second call. That is the safe side, and a person settles it in Themis.
5. One build system: Jenkins. Another one is a second implementation of `Builder`.

## Where this code lives

D8 puts the connector in its own repository. Until that repository exists it lives here as a
Go module of its own (`go.mod` in this directory), so the Themis build does not compile it and
it cannot import Themis code. To move it with its history:

```sh
# make a branch that holds only this directory
git subtree split --prefix=connectors/jenkins-rebuild -b connector-only
# push that branch to the new repository
git push <new-repository-url> connector-only:main
```

## Tests

```sh
go vet ./... && go test ./...
```

From the Themis repository root: `make connector-check`.
