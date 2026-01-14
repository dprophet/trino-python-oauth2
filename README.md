# trino-oauth2

The library supports [impediment-free] OAuth 2.0 authentication flows including [Client Credential](https://datatracker.ietf.org/doc/html/rfc6749#section-1.3.4), [Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628), and Authorization Code flows. This package is designed to make interaction with OAuth 2.0 flows as simple as possible.

### Install the package
`pip install trino.oauth2`

### Fetching Access Token Code Samples

#### Server Mode (Client Credentials)
- client_id: Required
- client_secret: Required

```python
from trino.oauth2 import OAuth2Client, ClientCredentialsConfig

oauth_client = OAuth2Client(
    config=ClientCredentialsConfig(
        client_id="<client_id>",
        client_secret="<client_secret>",
    )
)

access_token = oauth_client.token()
print(f"\nAccess token: {access_token}\n")
```

#### Device Mode
- client_id: Required
- client_secret: Optional (depending on provider)

```python
from trino.oauth2 import OAuth2Client, DeviceCodeConfig

# Note: poll_for_token=True will block until the user completes login in the browser
oauth_client = OAuth2Client(
    config=DeviceCodeConfig(
        client_id="<client_id>",
        client_secret="<client_secret>",
        poll_for_token=True
    ),
)

access_token = oauth_client.token()
print(f"\nAccess token: {access_token}\n")
```

#### Authorization Code Mode
- client_id: Required
- client_secret: Optional (depending on provider)
- redirect_uri: Required

```python
from trino.oauth2 import OAuth2Client, AuthorizationCodeConfig

oauth_client = OAuth2Client(
    config=AuthorizationCodeConfig(
        client_id="<client_id>",
        client_secret="<client_secret>",
        redirect_uri="http://localhost:8080/callback"
    )
)

access_token = oauth_client.token()
print(f"\nAccess token: {access_token}\n")
```

#### Advanced Functionality
In addition to the streamlined calls shown above, we offer a number of pieces of advanced functionality for users who require additional customization

| Parameter | Type | Description |
|----------|----------|----------|
| proxy_url    | string   | `proxy_url` can be used to set a destination where all traffic should be routed |

An example of using this:

```python
from trino.oauth2 import OAuth2Client, ClientCredentialsConfig

oauth_client = OAuth2Client(
    config=ClientCredentialsConfig(
        client_id="<client_id>",
        client_secret="<client_secret>",
    ),
    proxy_url="http://fake.proxy_url.com",
)

access_token = oauth_client.token()
print(f"\nAccess token: {access_token}\n")
```

### Use the access_token with your request
```python
headers = {}
headers['Authorization'] = f'Bearer {access_token}'
```

### Developing on OAuth Library

Example commands to run:

1. Create a virtual env `virtualenv venv --python=python3`
2. Activate the virtual env `source venv/bin/activate`
3. Build a wheel file `python -m build --wheel --outdir .`
4. Install the wheel file `pip install trino.oauth2-*.whl --force-reinstall`
5. Run the example `python example.py`

To run tests:
`pytest tests`

#### Running tests via the docker container

```bash
make restart-hydra
make container-test
```

#### Running tests locally (against Dockerized Hydra)

You must explicitly set the correct environment variables to point to localhost for local code development.
Testing still happens against the hydra docker container.

```bash
source .env.local
make restart-hydra
make test
```

