defmodule Oat.OAuth2.AuthorizationCodeGrant do
  @moduledoc """
  The authorization code grant: RFC 6749 §4.1 (https://www.rfc-editor.org/rfc/rfc6749#section-4.1).

      +----------+
      | Resource |
      |   Owner  |
      +----------+
           ^
           |
          (B)
      +----|-----+          Client Identifier      +---------------+
      |         -+----(A)-- & Redirection URI ---->|               |
      |  User-   |                                 | Authorization |
      |  Agent  -+----(B)-- User authenticates --->|     Server    |
      |          |                                 |               |
      |         -+----(C)-- Authorization Code ---<|               |
      +-|----|---+                                 +---------------+
        |    |                                         ^      v
       (A)  (C)                                        |      |
        |    |                                         |      |
        ^    v                                         |      |
      +---------+                                      |      |
      |         |>---(D)-- Authorization Code ---------'      |
      |  Client |          & Redirection URI                  |
      |         |                                             |
      |         |<---(E)----- Access Token -------------------'
      +---------+       (w/ Optional Refresh Token)

  * `validate/1` checks the authorization request from step (A).
  * `approve/2` and `deny/1` produce the redirect for step (C), once the
    resource owner has decided in step (B).
  * `exchange/2` handles the token request from step (D) and returns the
    token response for step (E).

  Lifetimes, in seconds, can be set with:

      config :oat, Oat.OAuth2.AuthorizationCodeGrant,
        authorization_code_lifetime: 600,
        access_token_lifetime: 3600

  Refresh tokens are not issued yet.
  """

  import Ecto.Query

  alias Oat.OAuth2.{
    AccessToken,
    AuthorizationCode,
    AuthorizationRequest,
    Client,
    Clients,
    Error,
    Params,
    RedirectURI,
    Scope,
    Syntax,
    Token,
    TokenResponse
  }

  alias Oat.Repo

  require Logger

  # §4.1.2 recommends a code lifetime of 10 minutes at most.
  @lifetimes [authorization_code_lifetime: 600, access_token_lifetime: 3600]

  @doc """
  Validates an authorization request (§4.1.1) from its raw query string.

  Returns:

    * `{:ok, request}` when the request is valid and the resource owner can be
      asked for a decision.
    * `{:error, :redirect, uri}` when the client and redirection URI are valid
      but the request is not. `uri` carries the error parameters (§4.1.2.1).
    * `{:error, :show, error}` when the client or redirection URI is missing or
      invalid. The server must not redirect; show `error` to the resource
      owner instead (§4.1.2.1, §10.15).
  """
  @spec validate(String.t() | nil) ::
          {:ok, AuthorizationRequest.t()}
          | {:error, :redirect, String.t()}
          | {:error, :show, Error.t()}
  def validate(query) do
    {params, repeated} = Params.decode(query)

    with {:ok, client} <- fetch_client(params, repeated),
         {:ok, redirect_uri} <- fetch_redirect_uri(client, params, repeated) do
      request = %AuthorizationRequest{
        client: client,
        redirect_uri: redirect_uri,
        bound_redirect_uri: params["redirect_uri"],
        state: if(Syntax.state?(params["state"]), do: params["state"])
      }

      with :ok <- check_repeated(repeated),
           :ok <- check_state(params, request.state),
           :ok <- check_response_type(params["response_type"]),
           {:ok, requested} <- parse_scope(params["scope"]),
           {:ok, scopes} <- resolve_scope(requested, client) do
        {:ok, %{request | requested_scopes: requested, scopes: scopes}}
      else
        {:error, %Error{} = error} -> {:error, :redirect, error_uri(request, error)}
      end
    end
  end

  defp fetch_client(params, repeated) do
    cond do
      "client_id" in repeated -> show("The client_id parameter is repeated")
      not Map.has_key?(params, "client_id") -> show("The client_id parameter is missing")
      not Syntax.client_id?(params["client_id"]) -> show("The client_id parameter is invalid")
      client = Clients.get(params["client_id"]) -> {:ok, client}
      true -> show("Unknown client")
    end
  end

  defp fetch_redirect_uri(client, params, repeated) do
    if "redirect_uri" in repeated do
      show("The redirect_uri parameter is repeated")
    else
      case RedirectURI.resolve(params["redirect_uri"], client.redirect_uris) do
        {:ok, uri} -> {:ok, uri}
        {:error, :missing_redirect_uri} -> show("The redirect_uri is missing")
        {:error, :invalid_redirect_uri} -> show("The redirect_uri is invalid")
      end
    end
  end

  defp show(description),
    do: {:error, :show, Error.new(:invalid_request, description: description)}

  defp check_repeated([]), do: :ok
  defp check_repeated([name | _]), do: {:error, Error.repeated(name)}

  # `state` is the request's state when it is valid, `nil` otherwise.
  defp check_state(%{"state" => _}, nil),
    do: Error.error(:invalid_request, "The state parameter is invalid")

  defp check_state(_params, _state), do: :ok

  defp check_response_type(nil),
    do: Error.error(:invalid_request, "The response_type parameter is missing")

  defp check_response_type(value) do
    case Params.response_type(value) do
      {:ok, types} ->
        if MapSet.equal?(types, MapSet.new(["code"])),
          do: :ok,
          else:
            Error.error(:unsupported_response_type, "Only the code response type is supported")

      {:error, :invalid_request} ->
        Error.error(:invalid_request, "The response_type parameter is invalid")
    end
  end

  defp parse_scope(value) do
    with {:error, :invalid_scope} <- Scope.parse(value),
         do: Error.error(:invalid_scope, "The scope parameter is invalid")
  end

  defp resolve_scope(requested, client) do
    allowed = MapSet.new(client.scopes)
    default = MapSet.new(client.default_scopes)

    with {:error, :invalid_scope} <- Scope.resolve(requested, allowed, default),
         do: Error.error(:invalid_scope, "The requested scope is not allowed")
  end

  @doc """
  The resource owner approved the request: issues an authorization code and
  returns the redirect to send the user-agent to (§4.1.2).

  If the code cannot be stored, returns `{:error, uri}` with a `server_error`
  redirect instead: a 500 status cannot reach the client (§4.1.2.1).
  """
  @spec approve(AuthorizationRequest.t(), String.t()) :: {:ok | :error, String.t()}
  def approve(%AuthorizationRequest{} = request, resource_owner_id)
      when is_binary(resource_owner_id) do
    code = Token.generate()
    now = DateTime.utc_now(:second)

    Repo.insert!(%AuthorizationCode{
      code_hash: Token.hash(code),
      client_id: request.client.id,
      resource_owner_id: resource_owner_id,
      redirect_uri: request.bound_redirect_uri,
      scopes: Enum.sort(request.scopes),
      requested_scopes: Enum.sort(request.requested_scopes),
      expires_at: Token.expires_at(now, lifetime(:authorization_code_lifetime))
    })

    {:ok, RedirectURI.append(request.redirect_uri, code: code, state: request.state)}
  rescue
    exception in [Postgrex.Error, DBConnection.ConnectionError] ->
      Logger.error(Exception.format(:error, exception, __STACKTRACE__))

      error =
        Error.new(:server_error, description: "The authorization server could not issue a code")

      {:error, error_uri(request, error)}
  end

  @doc """
  The resource owner denied the request: returns the `access_denied` redirect
  (§4.1.2.1).
  """
  @spec deny(AuthorizationRequest.t()) :: String.t()
  def deny(%AuthorizationRequest{} = request) do
    error = Error.new(:access_denied, description: "The resource owner denied the request")
    error_uri(request, error)
  end

  # The redirect that reports `error` to the client, with the request's state.
  defp error_uri(request, error),
    do: RedirectURI.append(request.redirect_uri, Error.to_params(%{error | state: request.state}))

  @doc """
  Exchanges an authorization code for an access token (§4.1.3, §4.1.4).

  `client` is the client already authenticated by
  `Oat.OAuth2.Clients.authenticate/2`; `params` are the token request
  parameters.

  A code can be used once. If it is used again the request fails and every
  token issued from it is revoked (§4.1.2, §10.5).
  """
  @spec exchange(Client.t(), map()) :: {:ok, map()} | {:error, Error.t()}
  def exchange(%Client{} = client, params) do
    with {:ok, code} <- fetch_code(params) do
      Repo.transact(fn ->
        AuthorizationCode
        |> where(code_hash: ^Token.hash(code))
        |> lock("FOR UPDATE")
        |> Repo.one()
        |> redeem(client, params)
      end)
      |> case do
        {:error, {:reused, code_id}} ->
          revoke_tokens_from(code_id)
          {:error, invalid_grant()}

        result ->
          result
      end
    end
  end

  defp fetch_code(%{"code" => code}) do
    if Syntax.code?(code),
      do: {:ok, code},
      else: Error.error(:invalid_request, "The code parameter is invalid")
  end

  defp fetch_code(_params), do: Error.error(:invalid_request, "The code parameter is missing")

  defp redeem(nil, _client, _params), do: {:error, invalid_grant()}

  defp redeem(%AuthorizationCode{redeemed_at: %DateTime{}} = code, _client, _params),
    do: {:error, {:reused, code.id}}

  defp redeem(%AuthorizationCode{} = code, client, params) do
    now = DateTime.utc_now(:second)

    # Issued to this client, not expired, and redirect_uri repeated exactly
    # when the authorization request included it (§4.1.3).
    if code.client_id == client.id and not Token.expired?(code.expires_at, now) and
         code.redirect_uri in [nil, params["redirect_uri"]],
       do: issue_token(code, now),
       else: {:error, invalid_grant()}
  end

  defp issue_token(code, now) do
    code |> Ecto.Changeset.change(redeemed_at: now) |> Repo.update!()

    token = Token.generate()
    lifetime = lifetime(:access_token_lifetime)

    Repo.insert!(%AccessToken{
      token_hash: Token.hash(token),
      client_id: code.client_id,
      authorization_code_id: code.id,
      resource_owner_id: code.resource_owner_id,
      scopes: code.scopes,
      expires_at: Token.expires_at(now, lifetime)
    })

    {:ok,
     TokenResponse.build(
       access_token: token,
       expires_in: lifetime,
       scope: MapSet.new(code.scopes),
       requested_scope: MapSet.new(code.requested_scopes)
     )}
  end

  defp revoke_tokens_from(code_id) do
    AccessToken
    |> where(authorization_code_id: ^code_id)
    |> where([t], is_nil(t.revoked_at))
    |> Repo.update_all(set: [revoked_at: DateTime.utc_now(:second)])
  end

  defp invalid_grant,
    do: Error.new(:invalid_grant, description: "The authorization code is invalid")

  defp lifetime(key) do
    :oat
    |> Application.get_env(__MODULE__, [])
    |> Keyword.get(key, Keyword.fetch!(@lifetimes, key))
  end
end
