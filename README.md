# oidc-cli

`oidc-cli` is a command-line tool that facilitates role assumption in AWS using OpenID Connect (OIDC) identity providers. It handles the OIDC authentication flow and AWS role assumption, making it easy to obtain temporary AWS credentials.

## Features

- Supports any OIDC-compatible identity provider
- Automatic browser-based authentication
- Credential caching for fast subsequent access
- Configurable as a credential_process in AWS CLI config
- Supports multiple output formats (shell exports or credential_process JSON)
- Cross-platform support (Linux, macOS, Windows)

## Installation

### From Source

```bash
cargo install --git https://github.com/robmdunn/oidc-cli
```

## Prerequisites

### Setting up an OIDC Identity Provider in AWS

Before configuring roles, you need to create an OIDC identity provider in AWS IAM. This tells AWS to trust your identity provider for federation.

See: [Create an OpenID Connect (OIDC) identity provider in IAM](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html)

### AWS Role Configuration

You'll need to configure your AWS IAM role with the appropriate trust policy. This policy determines which OIDC providers and users can assume the role.

See: [Create a role for OpenID Connect federation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html)

## Usage

### Basic Usage

To obtain AWS credentials using your OIDC provider:

```bash
# Using OIDC discovery URL (recommended)
oidc-cli --oidc-url https://auth.example.com \
       --client-id your-client-id \
       --role-arn arn:aws:iam::123456789012:role/YourRole

# Using explicit endpoints
oidc-cli --auth-endpoint https://auth.example.com/authorize \
       --token-endpoint https://auth.example.com/token \
       --client-id your-client-id \
       --role-arn arn:aws:iam::123456789012:role/YourRole
```

This will:
1. Open your browser for authentication
2. Exchange the token for AWS credentials
3. Print shell export commands for the credentials

### Shell Integration

To use the credentials in your current shell, run:

```bash
# Bash/Zsh
eval $(oidc-cli --oidc-url https://auth.example.com \
              --client-id your-client-id \
              --role-arn arn:aws:iam::123456789012:role/YourRole)

# PowerShell
oidc-cli --oidc-url https://auth.example.com `
       --client-id your-client-id `
       --role-arn arn:aws:iam::123456789012:role/YourRole | 
       ForEach-Object { Invoke-Expression $_ }
```

### AWS CLI Configuration

You can configure the AWS CLI to automatically use `oidc-cli` for credentials. Add this to your `~/.aws/config`:

```ini
[profile my-oidc-profile]
credential_process = oidc-cli --creds-process \
    --oidc-url https://auth.example.com \
    --client-id your-client-id \
    --role-arn arn:aws:iam::123456789012:role/YourRole

# For Windows, use:
[profile my-oidc-profile]
credential_process = oidc-cli.exe --creds-process ^
    --oidc-url https://auth.example.com ^
    --client-id your-client-id ^
    --role-arn arn:aws:iam::123456789012:role/YourRole
```

Then use the profile normally:

```bash
aws --profile my-oidc-profile s3 ls
```

## Options

```
Options:
  -o, --oidc-url <URL>             OIDC Provider URL for auto-discovery
  -a, --auth-endpoint <URL>        Auth endpoint (if not using OIDC URL)
  -t, --token-endpoint <URL>       Token endpoint (if not using OIDC URL)
  -c, --client-id <ID>            Client ID for OIDC provider
  -r, --role-arn <ARN>            AWS Role ARN to assume
      --role-session-name <NAME>   Role session name (default: your email)
      --scope <SCOPE>             OIDC scope (default: "openid email")
  -n, --no-cache                  Do not write credentials to cache
  -f, --force                     Bypass credential cache and force refresh
      --creds-process             Output credential_process format
  -h, --help                      Print help
  -V, --version                   Print version
```

## Cache Management

Credentials are cached by default at:
- Linux: `~/.cache/oidc-cli/aws-credentials.json`
- macOS: `~/Library/Caches/oidc-cli/aws-credentials.json`
- Windows: `%LOCALAPPDATA%\oidc-cli\aws-credentials.json`

To bypass the cache:
- Use `--force` to ignore cached credentials and force a new authentication
- Use `--no-cache` to prevent writing credentials to the cache

## License

MIT License - See [LICENSE](LICENSE) for details


